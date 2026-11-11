"""DEX-level static analysis through pinned Androguard 4.1.x.

This complements Apktool/Smali inspection with semantic method, string, permission,
and cross-reference information. It does not scan secrets or execute APK code.
"""
from __future__ import annotations

import json
import multiprocessing
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_ANALYSIS_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_EXTERNAL_METHODS = 100_000
MAX_INTERNAL_CALL_EDGES = 200_000
MAX_STRING_CANDIDATES = 100_000
URL_RE = re.compile(r"""(?:https?|wss?|ftp|grpc)://[^\s"'<>\\]+""", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_])"
)
IPV4_RE = re.compile(
    r"(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9.])"
)
ROUTE_RE = re.compile(
    r"""^/(?:api(?:/|$)|v[0-9]+(?:/|$)|graphql(?:/|$)|oauth(?:/|$)|auth(?:/|$)|"""
    r"""users?(?:/|$)|accounts?(?:/|$)|tokens?(?:/|$)|payments?(?:/|$)|"""
    r"""(?:health|status|login|register)(?:/|$))""",
    re.IGNORECASE,
)
RELATIVE_PATH_RE = re.compile(
    r"""^/?[A-Za-z0-9][A-Za-z0-9._~%{}:-]*(?:/[A-Za-z0-9][A-Za-z0-9._~%{}:-]*)+"""
    r"""(?:[?#][A-Za-z0-9._~%{}=&:+,;@/?-]*)?$"""
)
STATIC_PATH_PREFIXES = (
    "assets/", "res/", "smali/", "META-INF/", "android/", "kotlin/",
)
STATIC_FILE_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".xml", ".ttf", ".otf",
    ".so", ".dex", ".arsc", ".db", ".sqlite", ".html", ".css",
)
RATE_LIMIT_RE = re.compile(
    r"rate.?limit|retry-after|x-ratelimit|ratelimit-|backoff|exponential.?backoff|"
    r"too many requests|http.?429|token.?bucket|quota.?exceeded",
    re.IGNORECASE,
)
HEADER_RE = re.compile(
    r"(?i)\b(accept|accept-encoding|content-type|authorization|www-authenticate|"
    r"cookie|set-cookie|user-agent|origin|referer|if-none-match|etag|cache-control|"
    r"x-api-key|x-auth-token|x-request-id|retry-after|x-ratelimit-[a-z0-9-]+|"
    r"ratelimit-[a-z0-9-]+|x-[a-z0-9-]{2,60})\b"
)

API_OWNER_PREFIXES = {
    "network": (
        "Lokhttp3/", "Lretrofit2/", "Lcom/android/volley/", "Lcom/squareup/okhttp/",
        "Lorg/apache/http/", "Ljava/net/", "Ljavax/net/", "Ljavax/ws/rs/",
        "Lio/ktor/", "Lio/grpc/", "Lorg/chromium/net/", "Landroid/net/",
        "Lcom/google/api/client/", "Lcom/loopj/android/http/",
    ),
    "webview": ("Landroid/webkit/",),
    "cryptography": (
        "Ljava/security/", "Ljavax/crypto/", "Landroid/security/",
        "Lorg/bouncycastle/", "Ljavax/net/ssl/",
    ),
    "storage": (
        "Landroid/database/", "Landroid/content/ContentResolver;",
        "Landroid/content/SharedPreferences;", "Ljava/io/",
    ),
    "authentication": (
        "Landroid/accounts/", "Landroid/security/keystore/",
        "Lcom/auth0/", "Lcom/okta/", "Lcom/microsoft/identity/",
    ),
}


def _method_name(method: Any) -> str:
    return str(getattr(method, "full_name", None) or method)


def _safe_xrefs(method: Any) -> list[tuple[Any, Any, Any]]:
    try:
        return list(method.get_xref_from())
    except (AttributeError, TypeError, ValueError):
        return []


def _api_category(class_name: str) -> str:
    for category, prefixes in API_OWNER_PREFIXES.items():
        if class_name.startswith(prefixes):
            return category
    if class_name.startswith(("Ljava/", "Ljavax/", "Landroid/", "Lorg/")):
        return "platform_or_framework"
    return "external_library"


def _is_static_asset_path(value: str) -> bool:
    normalized = value.lstrip("/").lower()
    has_path_prefix = value.startswith("/") or normalized.startswith(STATIC_PATH_PREFIXES)
    return has_path_prefix and normalized.endswith(STATIC_FILE_SUFFIXES)


def _looks_like_relative_api_path(value: str) -> bool:
    """Return whether a DEX string has a conservative relative-path shape.

    This helper is only used when the string is cross-referenced from a method
    that also calls a recognized network/WebView API. It deliberately avoids
    classifying ordinary resource paths and common static asset filenames.
    """
    if not 2 <= len(value) <= 512 or value != value.strip():
        return False
    if any(character.isspace() or ord(character) < 32 for character in value):
        return False
    if "://" in value or value.startswith("//") or "\\" in value:
        return False
    if _is_static_asset_path(value):
        return False
    return bool(RELATIVE_PATH_RE.fullmatch(value))


def _analyze_in_worker(apk_path: str) -> dict[str, Any]:
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk = APK(apk_path)
    target_sdk = apk.get_effective_target_sdk_version()
    dex_payloads = list(apk.get_all_dex())
    if not dex_payloads:
        return {
            "status": "partial",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "apk": {
                "package": apk.get_package(),
                "version_code": apk.get_androidversion_code(),
                "version_name": apk.get_androidversion_name(),
                "min_sdk": apk.get_min_sdk_version(),
                "target_sdk": apk.get_target_sdk_version(),
                "effective_target_sdk": target_sdk,
            },
            "metrics": {"dex_files": 0, "classes": 0, "internal_methods": 0},
            "diagnostics": [{"code": "dex_not_found", "message": "APK contains no classes*.dex payload."}],
            "external_method_references": [],
            "internal_call_graph": [],
            "dex_api_strings": [],
            "permission_api_usage": [],
            "limitations": ["No DEX code was available for semantic cross-reference analysis."],
        }

    dx = Analysis()
    dex_objects = []
    for dex_bytes in dex_payloads:
        vm = DEX(dex_bytes, using_api=target_sdk)
        dx.add(vm)
        dex_objects.append(vm)
    dx.create_xref()

    internal_methods = [method for method in dx.get_internal_methods()]
    external_methods = [method for method in dx.get_external_methods()]
    internal_call_graph: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []
    truncated_internal = False
    for caller in internal_methods:
        for _class_obj, callee, offset in caller.get_xref_to():
            if len(internal_call_graph) >= MAX_INTERNAL_CALL_EDGES:
                truncated_internal = True
                break
            internal_call_graph.append({
                "caller": _method_name(caller),
                "callee": _method_name(callee),
                "offset": int(offset),
            })
        if truncated_internal:
            break
    if truncated_internal:
        diagnostics.append({
            "code": "internal_call_graph_limit",
            "message": f"Internal method-call graph was capped at {MAX_INTERNAL_CALL_EDGES} edges.",
        })

    external_references: list[dict[str, Any]] = []
    truncated_external = False
    network_caller_names: set[str] = set()
    for method in external_methods:
        callers = _safe_xrefs(method)
        if not callers:
            continue
        class_name = str(getattr(method, "class_name", ""))
        category = _api_category(class_name)
        if category in {"network", "webview"}:
            network_caller_names.update(_method_name(caller) for _class_obj, caller, _offset in callers)
        entry = {
            "owner": class_name,
            "method": str(getattr(method, "name", "")),
            "descriptor": str(getattr(method, "descriptor", "")),
            "full_name": _method_name(method),
            "category": category,
            "android_api": bool(method.is_android_api()),
            "call_sites": [],
        }
        for _class_obj, caller, offset in callers:
            entry["call_sites"].append({
                "caller": _method_name(caller),
                "caller_class": str(getattr(caller, "class_name", "")),
                "offset": int(offset),
            })
        external_references.append(entry)
        if len(external_references) >= MAX_EXTERNAL_METHODS:
            truncated_external = True
            break
    if truncated_external:
        diagnostics.append({
            "code": "external_method_limit",
            "message": f"External method inventory was capped at {MAX_EXTERNAL_METHODS} referenced methods.",
        })

    dex_api_strings: list[dict[str, Any]] = []
    seen_strings: set[str] = set()
    truncated_strings = False
    for string_item in dx.get_strings():
        value = str(string_item.get_value())
        url_matches = [match.group(0).rstrip(".,);]}:") for match in URL_RE.finditer(value)]
        domain_matches = [match.group(0).lower().rstrip(".") for match in DOMAIN_RE.finditer(value)]
        if _is_static_asset_path(value):
            domain_matches = []
        ip_matches = [match.group(0) for match in IPV4_RE.finditer(value)]
        string_xrefs = list(string_item.get_xref_from(with_offset=True))
        caller_names = {_method_name(caller) for _class_obj, caller, _offset in string_xrefs}
        network_call_context = bool(caller_names & network_caller_names)
        relative_path_candidate = (
            network_call_context and _looks_like_relative_api_path(value)
        )
        is_route = bool(ROUTE_RE.search(value)) or relative_path_candidate
        is_limit = bool(RATE_LIMIT_RE.search(value))
        headers = sorted({match.group(1).lower() for match in HEADER_RE.finditer(value)})
        if not (
            url_matches or domain_matches or ip_matches or is_route or is_limit or headers
        ):
            continue
        if value in seen_strings:
            continue
        seen_strings.add(value)
        references = []
        for class_obj, caller, offset in string_xrefs[:100]:
            references.append({
                "caller": _method_name(caller),
                "caller_class": str(getattr(caller, "class_name", "")),
                "offset": int(offset),
            })
        dex_api_strings.append({
            "value": value,
            "urls": url_matches,
            "domains": sorted(set(domain_matches)),
            "ip_addresses": sorted(set(ip_matches)),
            "route_candidate": is_route,
            "relative_path_candidate": relative_path_candidate,
            "network_call_context": network_call_context,
            "rate_limit_or_retry_indicator": is_limit,
            "http_header_candidates": headers,
            "references": references,
            "reference_count": len(string_xrefs),
        })
        if len(dex_api_strings) >= MAX_STRING_CANDIDATES:
            truncated_strings = True
            break
    if truncated_strings:
        diagnostics.append({
            "code": "dex_string_candidate_limit",
            "message": f"DEX API/config string inventory was capped at {MAX_STRING_CANDIDATES} candidates.",
        })

    permission_api_usage = []
    permission_mapping_status = "success"
    try:
        for api_method, permissions in dx.get_permissions(target_sdk):
            callers = [
                {
                    "caller": _method_name(caller),
                    "caller_class": str(getattr(caller, "class_name", "")),
                    "offset": int(offset),
                }
                for _class_obj, caller, offset in _safe_xrefs(api_method)
            ]
            permission_api_usage.append({
                "api_method": _method_name(api_method),
                "permissions": list(permissions),
                "call_sites": callers,
            })
    except (ValueError, OSError, KeyError) as exc:
        permission_mapping_status = "unavailable"
        diagnostics.append({
            "code": "permission_api_mapping_unavailable",
            "message": f"{type(exc).__name__}: {exc}",
        })

    internal_classes = list(dx.get_internal_classes())
    external_classes = list(dx.get_external_classes())
    return {
        "status": "partial" if diagnostics else "success",
        "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
        "apk": {
            "package": apk.get_package(),
            "version_code": apk.get_androidversion_code(),
            "version_name": apk.get_androidversion_name(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "effective_target_sdk": target_sdk,
            "declared_permissions": apk.get_permissions(),
            "implied_permissions": apk.get_uses_implied_permission_list(),
            "features": apk.get_features(),
            "libraries": apk.get_libraries(),
            "main_activity": apk.get_main_activity(),
        },
        "metrics": {
            "dex_files": len(dex_objects),
            "classes": len(internal_classes),
            "external_classes_referenced": len(external_classes),
            "internal_methods": len(internal_methods),
            "external_methods_referenced": len(external_references),
            "internal_call_graph_edges": len(internal_call_graph),
            "dex_api_string_candidates": len(dex_api_strings),
            "permission_api_usage": len(permission_api_usage),
        },
        "coverage": {
            "dex_parsing": "success",
            "method_cross_references": "partial" if truncated_internal else "success",
            "external_api_usage": "partial" if truncated_external else "success",
            "dex_api_strings": "partial" if truncated_strings else "success",
            "permission_api_usage": permission_mapping_status,
            "runtime_behavior": "not_performed",
        },
        "external_method_references": external_references,
        "internal_call_graph": internal_call_graph,
        "dex_api_strings": dex_api_strings,
        "permission_api_usage": permission_api_usage,
        "diagnostics": diagnostics,
        "limitations": [
            "Androguard static XREFs describe declared DEX references, not proof that every branch executes.",
            "Android API-to-permission mapping is version-specific and can be incomplete.",
            "Native libraries, reflection, obfuscated strings, dynamically loaded code, and server behavior require separate analysis.",
            "No application code was executed and no discovered API was contacted.",
        ],
    }


def _worker_entry(apk_path: str, send_connection) -> None:
    try:
        payload = _analyze_in_worker(apk_path)
    except Exception as exc:  # noqa: BLE001 - child process serializes parser exceptions for the parent
        payload = {
            "status": "failed",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "metrics": {},
            "coverage": {"dex_parsing": "failed"},
            "external_method_references": [],
            "internal_call_graph": [],
            "dex_api_strings": [],
            "permission_api_usage": [],
            "diagnostics": [{"code": "androguard_failed", "message": f"{type(exc).__name__}: {str(exc)[:2000]}"}],
            "limitations": ["Androguard DEX analysis did not complete."],
        }
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_ANALYSIS_OUTPUT_BYTES:
            encoded = json.dumps({
                "status": "partial",
                "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
                "metrics": {},
                "coverage": {"dex_parsing": "success", "report_serialization": "partial"},
                "external_method_references": [],
                "internal_call_graph": [],
                "dex_api_strings": [],
                "permission_api_usage": [],
                "diagnostics": [{
                    "code": "androguard_output_limit",
                    "message": f"DEX analysis output exceeded {MAX_ANALYSIS_OUTPUT_BYTES} bytes.",
                }],
                "limitations": ["The DEX analysis output was too large to serialize within the configured bound."],
            }, separators=(",", ":")).encode("utf-8")
        send_connection.send_bytes(encoded)
    finally:
        send_connection.close()


def _emit(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is None:
        return
    try:
        progress(message)
    except OSError:
        return


def analyze_apk_dex(
    apk_path: str | Path,
    *,
    timeout_seconds: int = 1800,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Analyze original APK DEX with bounded time and process isolation."""
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive.")
    path = Path(apk_path).expanduser()
    if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".apk":
        raise ValueError(f"DEX analysis requires a regular APK file: {path}")
    try:
        process_context = multiprocessing.get_context("fork")
    except ValueError as exc:
        raise RuntimeError("Androguard analysis requires Linux fork support.") from exc

    receive_connection, send_connection = process_context.Pipe(duplex=False)
    process = process_context.Process(
        target=_worker_entry,
        args=(str(path.resolve(strict=True)), send_connection),
        daemon=True,
    )
    started = time.monotonic()
    try:
        process.start()
        send_connection.close()
    except (OSError, RuntimeError) as exc:
        receive_connection.close()
        send_connection.close()
        raise RuntimeError(f"Cannot start Androguard analysis: {exc}") from exc

    payload_bytes: bytes | None = None
    try:
        while True:
            if receive_connection.poll(0.5):
                payload_bytes = receive_connection.recv_bytes(MAX_ANALYSIS_OUTPUT_BYTES + 4096)
                break
            if not process.is_alive():
                process.join(timeout=0.1)
                break
            elapsed = time.monotonic() - started
            if elapsed >= timeout_seconds:
                process.terminate()
                process.join(timeout=2)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=2)
                return {
                    "status": "timed_out",
                    "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
                    "metrics": {},
                    "coverage": {"dex_parsing": "timed_out"},
                    "external_method_references": [],
                    "internal_call_graph": [],
                    "dex_api_strings": [],
                    "permission_api_usage": [],
                    "diagnostics": [{
                        "code": "androguard_timeout",
                        "message": f"Androguard exceeded {timeout_seconds} seconds.",
                    }],
                    "limitations": ["DEX semantic analysis timed out; other static analysis results were retained."],
                }
            _emit(progress, f"[Androguard] DEX cross-reference analysis active — {int(elapsed)}s elapsed")
        if payload_bytes is None:
            return {
                "status": "failed",
                "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
                "metrics": {},
                "coverage": {"dex_parsing": "failed"},
                "external_method_references": [],
                "internal_call_graph": [],
                "dex_api_strings": [],
                "permission_api_usage": [],
                "diagnostics": [{
                    "code": "androguard_worker_exit",
                    "message": f"Androguard worker exited with status {process.exitcode} without a result.",
                }],
                "limitations": ["DEX semantic analysis did not return a complete result."],
            }
        result = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Androguard worker returned a non-object JSON payload.")
        return result
    except (EOFError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "status": "failed",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "metrics": {},
            "coverage": {"dex_parsing": "failed"},
            "external_method_references": [],
            "internal_call_graph": [],
            "dex_api_strings": [],
            "permission_api_usage": [],
            "diagnostics": [{"code": "androguard_result_error", "message": f"{type(exc).__name__}: {exc}"}],
            "limitations": ["DEX semantic analysis result was malformed or unavailable."],
        }
    finally:
        receive_connection.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        process.close()
