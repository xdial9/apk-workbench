"""DEX-level static analysis through pinned Androguard 4.1.x.

This complements Apktool/Smali inspection with semantic method, string, permission,
and cross-reference information. It does not scan secrets or execute APK code.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import re
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apkworkbench.analysis.surface.patterns import DOMAIN_RE

# CAP-FREE: No MAX_* caps. No truncation. Overflow is handled by writing
# the full payload to disk (see _worker_entry) instead of shrinking it to fit a pipe.
# Empty means empty. If count > 0, data must be present.
URL_RE = re.compile(r"""(?:https?|wss?|ftp|grpc)://[^\s"'<>\\]+""", re.IGNORECASE)
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


# Reflection call sites mapped for Crown Jewel #4 (DEX logic).
# key = "<owner>-><method>", value = the literal kind its first string argument
# carries, or None when the API takes no string argument at all.
REFLECTION_APIS: dict[str, str | None] = {
    "Ljava/lang/Class;->forName": "class_name",
    "Ljava/lang/Class;->getDeclaredMethod": "member_name",
    "Ljava/lang/Class;->getMethod": "member_name",
    "Ljava/lang/Class;->getDeclaredField": "member_name",
    "Ljava/lang/Class;->getField": "member_name",
    "Ljava/lang/reflect/Method;->invoke": None,
}
# DEX "no source file" sentinel (dex format: source_file_idx == NO_INDEX).
NO_SOURCE_FILE_INDEX = 0xFFFFFFFF


def _dex_index_of(dex_index_by_vm: dict[int, int], vm: Any) -> int | None:
    """Position of a DEX object in ``Analysis.vms`` (0-based), or None if unknown.

    One Analysis can hold several DEX files; this is the only record of which
    DEX an edge, class or string came from.
    """
    if vm is None:
        return None
    return dex_index_by_vm.get(id(vm))


def _method_dex_index(dex_index_by_vm: dict[int, int], method: Any) -> int | None:
    try:
        vm = method.get_vm()
    except (AttributeError, TypeError, ValueError):
        return None
    return _dex_index_of(dex_index_by_vm, vm)


def _class_dex_index(dex_index_by_vm: dict[int, int], class_def: Any) -> int | None:
    # ClassDefItem.CM is the parsing ClassManager; ClassManager.vm is the DEX.
    return _dex_index_of(dex_index_by_vm, getattr(getattr(class_def, "CM", None), "vm", None))


def _method_annotation_types(class_def: Any) -> dict[int, list[str]]:
    """method_idx -> annotation type descriptors, from the class annotation directory."""
    annotations: dict[int, list[str]] = {}
    directory = getattr(class_def, "annotations_directory_item", None)
    if directory is None:
        return annotations
    for method_annotation in directory.get_method_annotations():
        annotation_set = method_annotation.CM.get_annotation_set_item(
            method_annotation.get_annotations_off()
        )
        if annotation_set is None:
            continue
        types: list[str] = []
        for offset_item in annotation_set.get_annotation_off_item() or []:
            annotation_item = offset_item.get_annotation_item()
            types.append(
                str(annotation_item.CM.get_type(annotation_item.annotation.get_type_idx()))
            )
        annotations[int(method_annotation.get_method_idx())] = types
    return annotations


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


def _analyze_dex_payloads(
    dex_payloads: list[tuple[bytes, str | None]],
    target_sdk: int,
) -> dict[str, Any]:
    """Core DEX analysis from raw dex byte payloads (in-process, no multiprocessing).

    Each payload is paired with an optional ``source_citation`` — for top-level
    APK DEX this is ``None``; for container-embedded DEX it is the
    ``container!member`` chain (e.g. ``assets/plugins.apk!classes2.dex``).
    Every class/method/reference/string entry originating from a payload carries
    ``dex_source`` set to that citation, so the AI can tell which container a
    finding came from.

    Reuses the exact ``DEX(dex_bytes, using_api=target_sdk)`` call already used
    for the top-level case.
    """
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.dex import DEX

    if not dex_payloads:
        return {
            "status": "not_applicable",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "apk": {
                "package": None,
                "version_code": None,
                "version_name": None,
                "min_sdk": None,
                "target_sdk": target_sdk,
                "effective_target_sdk": target_sdk,
            },
            "metrics": {
                "dex_files": 0,
                "classes": 0,
                "internal_methods": 0,
                "class_model_count": 0,
                "method_model_count": 0,
                "string_class_index_entries": 0,
                "reflection_site_count": 0,
                "external_methods_without_callers": 0,
            },
            "coverage": {"code_model": "not_applicable"},
            "diagnostics": [{"code": "dex_not_found", "message": "No DEX payloads were provided for analysis."}],
            "class_model": [],
            "method_model": [],
            "string_class_index": {},
            "reflection_sites": [],
            "external_method_references": [],
            "internal_call_graph": [],
            "dex_api_strings": [],
            "permission_api_usage": [],
            "limitations": ["No DEX code was available for semantic cross-reference analysis."],
        }

    dx = Analysis()
    dex_objects = []
    dex_sources: dict[int, str | None] = {}
    for index, (dex_bytes, source_citation) in enumerate(dex_payloads):
        vm = DEX(dex_bytes, using_api=target_sdk)
        dx.add(vm)
        dex_objects.append(vm)
        dex_sources[id(vm)] = source_citation
    dx.create_xref()

    # DEX-of-origin index: position in dx.vms == order of payloads.
    dex_index_by_vm = {id(vm): index for index, vm in enumerate(dex_objects)}
    internal_methods = [method for method in dx.get_internal_methods()]
    external_methods = [method for method in dx.get_external_methods()]
    internal_call_graph: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []
    # CAP-FREE: no cap on call edges. Every edge is preserved.
    for caller in internal_methods:
        caller_dex = _method_dex_index(dex_index_by_vm, caller)
        for _class_obj, callee, offset in caller.get_xref_to():
            internal_call_graph.append({
                "caller": _method_name(caller),
                "callee": _method_name(callee),
                "offset": int(offset),
                "dex_class": caller_dex,
                "dex_source": dex_sources.get(
                    id(dx.vms[caller_dex]) if caller_dex is not None else None
                ),
            })

    # ---- P3 code model: class inventory + method inventory --------------------
    internal_classes = list(dx.get_internal_classes())
    class_model: list[dict[str, Any]] = []
    method_model: list[dict[str, Any]] = []
    code_model_status = "success" if internal_classes else "not_applicable"
    for class_analysis in internal_classes:
        try:
            class_def = class_analysis.get_vm_class()
            class_name = str(class_def.get_name())
            method_annotations = _method_annotation_types(class_def)
            source_file_index = int(class_def.get_source_file_idx())
            source_file: str | None = None
            if source_file_index != NO_SOURCE_FILE_INDEX:
                source_value = class_def.CM.get_string(source_file_index)
                source_file = str(source_value) if source_value is not None else None
            methods = list(class_analysis.get_methods())
            fields = list(class_analysis.get_fields())
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            code_model_status = "partial"
            diagnostics.append({
                "code": "class_model_incomplete",
                "message": f"{type(exc).__name__}: {exc}",
            })
            continue
        class_dex_index = _class_dex_index(dex_index_by_vm, class_def)
        class_source = dex_sources.get(
            id(dx.vms[class_dex_index]) if class_dex_index is not None else None
        )
        class_model.append({
            "dex_index": class_dex_index,
            "dex_source": class_source,
            "class_name": class_name,
            "access_flags": str(class_def.get_access_flags_string()),
            "superclass": str(class_def.get_superclassname()),
            "interfaces": [str(name) for name in class_def.get_interfaces()],
            "source_file": source_file,
            "method_count": len(methods),
            "field_count": len(fields),
            "annotations": [str(name) for name in class_def.get_annotations()],
        })
        for method in methods:
            try:
                method_index = int(method.get_method().get_method_idx())
            except (AttributeError, TypeError, ValueError):
                method_index = -1
            method_model.append({
                "class_name": class_name,
                "dex_index": class_dex_index,
                "dex_source": class_source,
                "method_name": str(method.name),
                "full_name": _method_name(method),
                "access_flags": str(method.get_access_flags_string()),
                "descriptor": str(method.descriptor),
                "annotations": list(method_annotations.get(method_index, [])),
            })
    if len(class_model) != len(internal_classes):
        code_model_status = "partial"

    external_references: list[dict[str, Any]] = []
    network_caller_names: set[str] = set()
    external_methods_without_callers = 0
    # CAP-FREE: no cap on external methods. Every referenced method is preserved.
    for method in external_methods:
        callers = _safe_xrefs(method)
        class_name = str(getattr(method, "class_name", ""))
        category = _api_category(class_name)
        if category in {"network", "webview"}:
            network_caller_names.update(_method_name(caller) for _class_obj, caller, _offset in callers)
        if not callers:
            external_methods_without_callers += 1
        entry = {
            "owner": class_name,
            "method": str(getattr(method, "name", "")),
            "descriptor": str(getattr(method, "descriptor", "")),
            "full_name": _method_name(method),
            "category": category,
            "android_api": bool(method.is_android_api()),
            "dex_class": None,
            "dex_source": None,
            "call_sites": [],
        }
        for _class_obj, caller, offset in callers:
            caller_dex = _method_dex_index(dex_index_by_vm, caller)
            entry["call_sites"].append({
                "caller": _method_name(caller),
                "caller_class": str(getattr(caller, "class_name", "")),
                "offset": int(offset),
                "dex_class": caller_dex,
                "dex_source": dex_sources.get(
                    id(dx.vms[caller_dex]) if caller_dex is not None else None
                ),
            })
        caller_dex_indexes = {site["dex_class"] for site in entry["call_sites"]}
        if len(caller_dex_indexes) == 1:
            entry["dex_class"] = entry["call_sites"][0]["dex_class"]
            entry["dex_source"] = entry["call_sites"][0]["dex_source"]
        external_references.append(entry)

    # ---- P3 reflection sites (one-hop, never guessed) -------------------------
    reflection_sites: list[dict[str, Any]] = []
    reflection_callers: set[str] = set()
    string_evidence_by_caller: dict[str, list[tuple[int, str]]] = {}
    for entry in external_references:
        api = f"{entry['owner']}->{entry['method']}"
        if api not in REFLECTION_APIS:
            continue
        for call_site in entry["call_sites"]:
            reflection_callers.add(call_site["caller"])
            reflection_sites.append({
                "caller": call_site["caller"],
                "caller_class": call_site["caller_class"],
                "api": api,
                "offset": call_site["offset"],
                "argument_resolved": False,
                "resolved_target": None,
                "resolution_kind": None,
                "unresolved_reason": None,
            })

    dex_api_strings: list[dict[str, Any]] = []
    seen_strings: set[str] = set()
    string_class_index: dict[str, list[str]] = {}
    # CAP-FREE: no cap on string candidates. Every candidate is preserved.
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
        if string_xrefs:
            referencing_classes = sorted(
                {
                    str(getattr(caller, "class_name", ""))
                    for _class_obj, caller, _offset in string_xrefs
                }
                - {""}
            )
            if referencing_classes:
                string_class_index[value] = referencing_classes
            for _class_obj, caller, offset in string_xrefs:
                caller_name = _method_name(caller)
                if caller_name in reflection_callers:
                    string_evidence_by_caller.setdefault(caller_name, []).append(
                        (int(offset), value)
                    )
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
        # CAP-FREE: keep ALL callers per string.
        for class_obj, caller, offset in string_xrefs:
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

    # One-hop reflection resolution.
    for site in reflection_sites:
        resolution_kind = REFLECTION_APIS[site["api"]]
        if resolution_kind is None:
            site["unresolved_reason"] = "no_literal_argument"
            continue
        preceding = [
            (offset, target)
            for offset, target in string_evidence_by_caller.get(site["caller"], [])
            if offset < site["offset"]
        ]
        if not preceding:
            site["unresolved_reason"] = "no_string_constant_before_call_site"
            continue
        preceding.sort(key=lambda item: (-item[0], item[1]))
        site["argument_resolved"] = True
        site["resolved_target"] = preceding[0][1]
        site["resolution_kind"] = resolution_kind
    reflection_sites.sort(key=lambda site: (site["caller"], site["offset"], site["api"]))

    permission_api_usage = []
    permission_mapping_status = "success"
    try:
        for api_method, permissions in dx.get_permissions(target_sdk):
            permission_api_usage.append({
                "api": api_method,
                "permissions": list(permissions),
            })
    except Exception as exc:  # noqa: BLE001
        permission_mapping_status = "partial"
        diagnostics.append({
            "code": "permission_mapping_failed",
            "message": f"{type(exc).__name__}: {exc}",
        })

    return {
        "status": "success",
        "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
        "apk": {
            "package": None,
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "target_sdk": target_sdk,
            "effective_target_sdk": target_sdk,
        },
        "metrics": {
            "dex_files": len(dex_objects),
            "classes": len(internal_classes),
            "external_classes_referenced": 0,
            "internal_methods": len(internal_methods),
            "external_methods_referenced": len(external_references),
            "external_methods_without_callers": external_methods_without_callers,
            "internal_call_graph_edges": len(internal_call_graph),
            "dex_api_string_candidates": len(dex_api_strings),
            "permission_api_usage": len(permission_api_usage),
            "class_model_count": len(class_model),
            "method_model_count": len(method_model),
            "string_class_index_entries": len(string_class_index),
            "reflection_site_count": len(reflection_sites),
        },
        "coverage": {
            "dex_parsing": "success",
            "method_cross_references": "success",
            "external_api_usage": "success",
            "dex_api_strings": "success",
            "permission_api_usage": permission_mapping_status,
            "code_model": code_model_status,
            "runtime_behavior": "not_performed",
        },
        "class_model": class_model,
        "method_model": method_model,
        "string_class_index": string_class_index,
        "reflection_sites": reflection_sites,
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


def _analyze_in_worker(apk_path: str) -> dict[str, Any]:
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk = APK(apk_path)
    target_sdk = apk.get_effective_target_sdk_version()
    dex_payloads = list(apk.get_all_dex())
    if not dex_payloads:
        return {
            "status": "not_applicable",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "apk": {
                "package": apk.get_package(),
                "version_code": apk.get_androidversion_code(),
                "version_name": apk.get_androidversion_name(),
                "min_sdk": apk.get_min_sdk_version(),
                "target_sdk": apk.get_target_sdk_version(),
                "effective_target_sdk": target_sdk,
            },
            "metrics": {
                "dex_files": 0,
                "classes": 0,
                "internal_methods": 0,
                "class_model_count": 0,
                "method_model_count": 0,
                "string_class_index_entries": 0,
                "reflection_site_count": 0,
                "external_methods_without_callers": 0,
            },
            "coverage": {"code_model": "not_applicable"},
            "diagnostics": [{"code": "dex_not_found", "message": "APK contains no classes*.dex payload."}],
            "class_model": [],
            "method_model": [],
            "string_class_index": {},
            "reflection_sites": [],
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

    # DEX-of-origin index: position in dx.vms == order of classes*.dex payloads.
    dex_index_by_vm = {id(vm): index for index, vm in enumerate(dex_objects)}
    internal_methods = [method for method in dx.get_internal_methods()]
    external_methods = [method for method in dx.get_external_methods()]
    internal_call_graph: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []
    # CAP-FREE: no cap on call edges. Every edge is preserved.
    for caller in internal_methods:
        caller_dex = _method_dex_index(dex_index_by_vm, caller)
        for _class_obj, callee, offset in caller.get_xref_to():
            internal_call_graph.append({
                "caller": _method_name(caller),
                "callee": _method_name(callee),
                "offset": int(offset),
                # Which DEX the edge comes from — one Analysis spans every DEX.
                "dex_class": caller_dex,
                # Deduction link: caller -> callee, for Crown Jewel mapping (DEX logic)
            })

    # ---- P3 code model: class inventory + method inventory --------------------
    # Deduction base for Crown Jewel #4: every class and method is named, joined
    # by class_name/full_name, and every entry can be traced to its DEX index.
    internal_classes = list(dx.get_internal_classes())
    class_model: list[dict[str, Any]] = []
    method_model: list[dict[str, Any]] = []
    code_model_status = "success" if internal_classes else "not_applicable"
    for class_analysis in internal_classes:
        try:
            class_def = class_analysis.get_vm_class()
            class_name = str(class_def.get_name())
            method_annotations = _method_annotation_types(class_def)
            source_file_index = int(class_def.get_source_file_idx())
            source_file: str | None = None
            if source_file_index != NO_SOURCE_FILE_INDEX:
                source_value = class_def.CM.get_string(source_file_index)
                source_file = str(source_value) if source_value is not None else None
            methods = list(class_analysis.get_methods())
            fields = list(class_analysis.get_fields())
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            # A class we cannot describe is a named skip, never a silent drop.
            code_model_status = "partial"
            diagnostics.append({
                "code": "class_model_incomplete",
                "message": f"{type(exc).__name__}: {exc}",
            })
            continue
        class_model.append({
            "dex_index": _class_dex_index(dex_index_by_vm, class_def),
            "class_name": class_name,
            "access_flags": str(class_def.get_access_flags_string()),
            "superclass": str(class_def.get_superclassname()),
            "interfaces": [str(name) for name in class_def.get_interfaces()],
            "source_file": source_file,
            "method_count": len(methods),
            "field_count": len(fields),
            "annotations": [str(name) for name in class_def.get_annotations()],
        })
        for method in methods:
            try:
                method_index = int(method.get_method().get_method_idx())
            except (AttributeError, TypeError, ValueError):
                method_index = -1
            method_model.append({
                "class_name": class_name,
                "method_name": str(method.name),
                "full_name": _method_name(method),
                "access_flags": str(method.get_access_flags_string()),
                "descriptor": str(method.descriptor),
                "annotations": list(method_annotations.get(method_index, [])),
            })
    if len(class_model) != len(internal_classes):
        code_model_status = "partial"

    external_references: list[dict[str, Any]] = []
    network_caller_names: set[str] = set()
    external_methods_without_callers = 0
    # CAP-FREE: no cap on external methods. Every referenced method is preserved.
    for method in external_methods:
        callers = _safe_xrefs(method)
        class_name = str(getattr(method, "class_name", ""))
        category = _api_category(class_name)
        if category in {"network", "webview"}:
            network_caller_names.update(_method_name(caller) for _class_obj, caller, _offset in callers)
        if not callers:
            # D4: a referenced external method with zero call sites is still a
            # finding. Emit it with call_sites=[] and count it — never drop it.
            external_methods_without_callers += 1
        entry = {
            "owner": class_name,
            "method": str(getattr(method, "name", "")),
            "descriptor": str(getattr(method, "descriptor", "")),
            "full_name": _method_name(method),
            "category": category,
            "android_api": bool(method.is_android_api()),
            # External methods have no owning DEX; a single caller DEX is used
            # when every call site shares one, otherwise None (see call_sites).
            "dex_class": None,
            "call_sites": [],
        }
        for _class_obj, caller, offset in callers:
            entry["call_sites"].append({
                "caller": _method_name(caller),
                "caller_class": str(getattr(caller, "class_name", "")),
                "offset": int(offset),
                "dex_class": _method_dex_index(dex_index_by_vm, caller),
            })
        caller_dex_indexes = {site["dex_class"] for site in entry["call_sites"]}
        if len(caller_dex_indexes) == 1:
            entry["dex_class"] = entry["call_sites"][0]["dex_class"]
        external_references.append(entry)

    # ---- P3 reflection sites (one-hop, never guessed) -------------------------
    reflection_sites: list[dict[str, Any]] = []
    reflection_callers: set[str] = set()
    string_evidence_by_caller: dict[str, list[tuple[int, str]]] = {}
    for entry in external_references:
        api = f"{entry['owner']}->{entry['method']}"
        if api not in REFLECTION_APIS:
            continue
        for call_site in entry["call_sites"]:
            reflection_callers.add(call_site["caller"])
            reflection_sites.append({
                "caller": call_site["caller"],
                "caller_class": call_site["caller_class"],
                "api": api,
                "offset": call_site["offset"],
                "argument_resolved": False,
                "resolved_target": None,
                "resolution_kind": None,
                "unresolved_reason": None,
            })

    dex_api_strings: list[dict[str, Any]] = []
    seen_strings: set[str] = set()
    string_class_index: dict[str, list[str]] = {}
    # CAP-FREE: no cap on string candidates. Every candidate is preserved.
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
        # Deduction link (P3): string value -> every class that references it.
        # Built before the endpoint filter below, so class-name literals passed to
        # Class.forName are indexed too. A value missing from this index is a value
        # no internal class references — never a dropped one.
        if string_xrefs:
            referencing_classes = sorted(
                {
                    str(getattr(caller, "class_name", ""))
                    for _class_obj, caller, _offset in string_xrefs
                }
                - {""}
            )
            if referencing_classes:
                string_class_index[value] = referencing_classes
            # One-hop reflection evidence: constants seen in a method that also
            # calls a reflection API, with the offset that orders them.
            for _class_obj, caller, offset in string_xrefs:
                caller_name = _method_name(caller)
                if caller_name in reflection_callers:
                    string_evidence_by_caller.setdefault(caller_name, []).append(
                        (int(offset), value)
                    )
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
        # CAP-FREE: was capped at 100 callers per string — that dropped callers. Keep ALL callers.
        # Deduction link: string value -> every method that references it.
        for class_obj, caller, offset in string_xrefs:
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

    # One-hop reflection resolution: only APIs whose first string argument is a
    # literal are resolved, using the nearest preceding string constant in the same
    # method. Everything else stays unresolved WITH a reason — never a guessed target.
    for site in reflection_sites:
        resolution_kind = REFLECTION_APIS[site["api"]]
        if resolution_kind is None:
            site["unresolved_reason"] = "no_literal_argument"
            continue
        preceding = [
            (offset, target)
            for offset, target in string_evidence_by_caller.get(site["caller"], [])
            if offset < site["offset"]
        ]
        if not preceding:
            site["unresolved_reason"] = "no_string_constant_before_call_site"
            continue
        preceding.sort(key=lambda item: (-item[0], item[1]))
        site["argument_resolved"] = True
        site["resolved_target"] = preceding[0][1]
        site["resolution_kind"] = resolution_kind
    reflection_sites.sort(key=lambda site: (site["caller"], site["offset"], site["api"]))

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
            "external_methods_without_callers": external_methods_without_callers,
            "internal_call_graph_edges": len(internal_call_graph),
            "dex_api_string_candidates": len(dex_api_strings),
            "permission_api_usage": len(permission_api_usage),
            "class_model_count": len(class_model),
            "method_model_count": len(method_model),
            "string_class_index_entries": len(string_class_index),
            "reflection_site_count": len(reflection_sites),
        },
        "coverage": {
            "dex_parsing": "success",
            "method_cross_references": "success",
            "external_api_usage": "success",
            "dex_api_strings": "success",
            "permission_api_usage": permission_mapping_status,
            "code_model": code_model_status,
            "runtime_behavior": "not_performed",
            # 100% = file-coverage: every DEX file accounted, every edge/string/method preserved.
            # Not runtime proof: reflection / dynamic loading / server behavior still not proven.
        },
        "class_model": class_model,
        "method_model": method_model,
        "string_class_index": string_class_index,
        "reflection_sites": reflection_sites,
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
            "reflection_sites resolves only literal string arguments (nearest preceding const-string in the same method); java/lang/reflect/Method->invoke arguments are objects, so its target stays unresolved with a reason.",
            "string_class_index lists only values that at least one internal class references; a value absent from it is unreferenced, not dropped.",
            "DEX strings and classes are keyed by value/name across DEX files (Androguard D5), so a value declared in two DEX files keeps one entry.",
        ],
    }


def _worker_entry(apk_path: str, send_connection, output_path: str) -> None:
    """Worker: analyze, write FULL payload to disk, send only a tiny ack via pipe.

    CAP-FREE FIX: The old code did json.dumps(payload) then if >64MB replaced
    the whole payload with [] + metrics={}. That lied: AI read [] as "no API usage"
    when truth was "too much API usage to fit a pipe."
    New behavior: payload is written to output_path on disk (no size limit).
    Pipe carries only b"OK" (or b"FAIL"). Parent reads the file. No truncation.
    """
    try:
        try:
            payload = _analyze_in_worker(apk_path)
        except Exception as exc:  # noqa: BLE001 - child serializes parser exceptions
            payload = {
                "status": "failed",
                "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
                "metrics": {},
                "coverage": {"dex_parsing": "failed", "code_model": "failed"},
                "class_model": [],
                "method_model": [],
                "string_class_index": {},
                "reflection_sites": [],
                "external_method_references": [],
                "internal_call_graph": [],
                "dex_api_strings": [],
                "permission_api_usage": [],
                "diagnostics": [{"code": "androguard_failed", "message": f"{type(exc).__name__}: {str(exc)[:2000]}"}],
                "limitations": ["Androguard DEX analysis did not complete."],
            }
        # Write full payload to disk — no cap, no truncation, no empty replacement.
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
        try:
            send_connection.send_bytes(b"OK")
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001 - worker must not hang parent
        try:
            send_connection.send_bytes(b"FAIL:" + str(exc)[:500].encode("utf-8", "ignore"))
        except Exception:
            pass
    finally:
        try:
            send_connection.close()
        except Exception:
            pass


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
    """Analyze original APK DEX with bounded time and process isolation.

    CAP-FREE: Worker writes full result to a temp file on disk, parent reads it.
    Pipe carries only a tiny ack. No 64MB pipe cap, no empty replacement.
    API is unchanged for callers (apk_surface.py): still returns a dict.
    """
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive.")
    path = Path(apk_path).expanduser()
    if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".apk":
        raise ValueError(f"DEX analysis requires a regular APK file: {path}")
    try:
        process_context = multiprocessing.get_context("fork")
    except ValueError as exc:
        raise RuntimeError("Androguard analysis requires Linux fork support.") from exc

    # Temp file on disk for the full payload — this is the shard, not a pipe.
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="androguard_dex_", suffix=".json")
    os.close(tmp_fd)
    # Ensure empty file exists so worker can overwrite it
    try:
        os.unlink(tmp_path)
    except FileNotFoundError:
        pass

    receive_connection, send_connection = process_context.Pipe(duplex=False)
    process = process_context.Process(
        target=_worker_entry,
        args=(str(path.resolve(strict=True)), send_connection, tmp_path),
        daemon=True,
    )
    started = time.monotonic()
    try:
        process.start()
        send_connection.close()
    except (OSError, RuntimeError) as exc:
        receive_connection.close()
        send_connection.close()
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise RuntimeError(f"Cannot start Androguard analysis: {exc}") from exc

    ack: bytes | None = None
    try:
        while True:
            if receive_connection.poll(0.5):
                try:
                    ack = receive_connection.recv_bytes()
                except EOFError:
                    ack = None
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
                    "coverage": {"dex_parsing": "timed_out", "code_model": "timed_out"},
                    "class_model": [],
                    "method_model": [],
                    "string_class_index": {},
                    "reflection_sites": [],
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
        # Parent reads FULL payload from disk — no size cap.
        if ack is None or not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
            return {
                "status": "failed",
                "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
                "metrics": {},
                "coverage": {"dex_parsing": "failed", "code_model": "failed"},
                "class_model": [],
                "method_model": [],
                "string_class_index": {},
                "reflection_sites": [],
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
        with open(tmp_path, "r", encoding="utf-8") as fh:
            result = json.load(fh)
        if not isinstance(result, dict):
            raise ValueError("Androguard worker returned a non-object JSON payload.")
        # Safety: if worker wrote a failed payload, return it as-is (it is honest, not a cap lie)
        return result
    except (EOFError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "status": "failed",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "metrics": {},
            "coverage": {"dex_parsing": "failed", "code_model": "failed"},
            "class_model": [],
            "method_model": [],
            "string_class_index": {},
            "reflection_sites": [],
            "external_method_references": [],
            "internal_call_graph": [],
            "dex_api_strings": [],
            "permission_api_usage": [],
            "diagnostics": [{"code": "androguard_result_error", "message": f"{type(exc).__name__}: {exc}"}],
            "limitations": ["DEX semantic analysis result was malformed or unavailable."],
        }
    finally:
        receive_connection.close()
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        process.close()
