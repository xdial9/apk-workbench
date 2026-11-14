"""Broad, deterministic static surface inspection for Apktool-decoded APKs.

This analyzer reports evidence-backed static indicators and inventories. It does
not execute APK code, contact discovered endpoints, or claim runtime verification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from apkworkbench.analysis.androguard_dex import analyze_apk_dex
from apkworkbench.analysis.surface.classify import (
    TEXT_SUFFIXES,
    classify_decoded_tree,
    inventory_apk_zip,
)
from apkworkbench.analysis.surface.sweep import SweepState
from apkworkbench.analysis.surface.manifest_v2 import (
    parse_backup_rules,
    parse_manifest_v2,
    parse_network_security_config,
)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.BLUETOOTH_CONNECT",
}

DEPENDENCY_MARKERS = {
    "Firebase": ("com/google/firebase/", "com.google.firebase"),
    "Google Play Services": ("com/google/android/gms/", "com.google.android.gms"),
    "OkHttp": ("okhttp3/", "okhttp3."),
    "Retrofit": ("retrofit2/", "retrofit2."),
    "Square": ("com/squareup/", "com.squareup"),
    "Facebook SDK": ("com/facebook/", "com.facebook."),
    "Flutter": ("io/flutter/", "io.flutter."),
    "React Native": ("com/facebook/react/", "com.facebook.react"),
    "Kotlin": ("kotlin/", "kotlin."),
    "Jetpack": ("androidx/", "androidx."),
    "Realm": ("io/realm/", "io.realm."),
    "Sentry": ("io/sentry/", "io.sentry."),
    "AppsFlyer": ("com/appsflyer/", "com.appsflyer"),
    "Adjust": ("com/adjust/", "com.adjust."),
    "Branch": ("io/branch/", "io.branch."),
    "OneSignal": ("com/onesignal/", "com.onesignal."),
    "AWS SDK / Amplify": ("com/amazonaws/", "com.amazonaws.", "com/amplifyframework/", "com.amplifyframework."),
    "Azure / MSAL": ("com/microsoft/azure/", "com.microsoft.azure.", "com/microsoft/identity/", "com.microsoft.identity."),
    "Supabase": ("io/supabase/", "io.supabase."),
    "Appwrite": ("io/appwrite/", "io.appwrite."),
    "Auth0": ("com/auth0/", "com.auth0."),
    "Okta": ("com/okta/", "com.okta."),
    "Stripe": ("com/stripe/", "com.stripe."),
    "Adyen": ("com/adyen/", "com.adyen."),
    "Braintree": ("com/braintreepayments/", "com.braintreepayments."),
    "Twilio": ("com/twilio/", "com.twilio."),
    "RevenueCat": ("com/revenuecat/", "com.revenuecat."),
    "SendGrid": ("com/sendgrid/", "com.sendgrid."),
}

# These are review leads, not automatic vulnerability verdicts.
CODE_RULES = (
    ("webview_javascript_interface", "webview", "high", "JavaScript bridge exposed to WebView",
     r"addJavascriptInterface", 0.94,
     "A JavaScript interface is registered. Review the exposed methods and the WebView trust boundary."),
    ("webview_file_access", "webview", "medium", "WebView file access API used",
     r"setAllowFileAccess|setAllowContentAccess", 0.82,
     "A WebView file/content-access setting is invoked. Inspect the value and loaded content origin."),
    ("webview_universal_file_access", "webview", "high", "WebView universal file URL access API used",
     r"setAllowUniversalAccessFromFileURLs", 0.90,
     "This setting can widen file-origin access when enabled; inspect the supplied boolean value."),
    ("webview_debugging", "webview", "medium", "WebView debugging API used",
     r"setWebContentsDebuggingEnabled", 0.82,
     "Inspect whether WebView debugging is enabled in production builds."),
    ("webview_mixed_content", "webview", "medium", "WebView mixed-content setting used",
     r"setMixedContentMode", 0.78,
     "Inspect the configured mode and whether HTTPS pages can load HTTP content."),
    ("dynamic_code_loading", "dynamic_code", "high", "Dynamic code-loading API referenced",
     r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader", 0.90,
     "Code may be loaded at runtime. Trace the source, integrity checks, and loaded code origin."),
    ("process_execution", "process_execution", "medium", "Process execution API referenced",
     r"Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;", 0.88,
     "Review command construction, input sources, and privilege context."),
    ("custom_tls_trust", "network_security", "info", "Custom TLS trust implementation referenced",
     r"X509TrustManager|checkServerTrusted|HostnameVerifier", 0.75,
     "A custom certificate/hostname verification implementation may exist; inspect its behavior."),
    ("ssl_error_proceed", "network_security", "high", "WebView SSL error handler may proceed past certificate error",
     r"SslErrorHandler;->proceed|\.proceed\(\)", 0.88,
     "Review whether this call proceeds after a TLS certificate error and under which conditions."),
    ("trust_all_certificates", "network_security", "high", "Trust-all certificate implementation indicator",
     r"TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier", 0.92,
     "A trust-all or allow-all verifier marker is present; inspect the implementation and call path."),
    ("mutable_pending_intent", "components", "medium", "Mutable PendingIntent flag referenced",
     r"FLAG_MUTABLE|0x02000000", 0.72,
     "Review whether the mutable PendingIntent is necessary and whether its creator is exposed."),
    ("world_accessible_file_mode", "data_storage", "high", "Legacy world-readable/writable file mode referenced",
     r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", 0.90,
     "A deprecated world-accessible file mode is referenced; check whether it can be reached on supported Android versions."),
    ("weak_tls_protocol", "cryptography", "high", "Legacy TLS/SSL protocol string present",
     r"""["'](?:SSL|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1)["']""", 0.90,
     "A legacy protocol identifier is present. Confirm whether it is used by an active TLS context."),
    ("weak_cipher", "cryptography", "high", "Weak or legacy cipher identifier present",
     r"""["'](?:DES|DESede|3DES|RC2|RC4|AES/ECB[^"']*)["']""", 0.90,
     "A weak or legacy cipher identifier is present. Confirm use and data sensitivity."),
    ("insecure_random", "cryptography", "medium", "Non-cryptographic random API referenced",
     r"Ljava/util/Random;|java\.util\.Random", 0.78,
     "This random generator is not designed for security-sensitive values."),
    ("sql_raw_query", "data_storage", "medium", "Raw SQL query API referenced",
     r"rawQuery|execSQL", 0.72,
     "Review query construction for untrusted string concatenation and parameter binding."),
    ("external_storage", "data_storage", "medium", "Shared/external storage API referenced",
     r"getExternalStorageDirectory|DIRECTORY_DOWNLOADS|WRITE_EXTERNAL_STORAGE", 0.78,
     "Review whether sensitive application data is written to shared storage."),
    ("insecure_http", "network", "medium", "Cleartext HTTP URL present in decoded files",
     r"""http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""", 0.96,
     "A cleartext URL is present. Determine whether it carries sensitive traffic or is documentation/test data."),
    ("webview_javascript", "webview", "info", "WebView JavaScript configuration API referenced",
     r"setJavaScriptEnabled", 0.78,
     "Review whether JavaScript is enabled for untrusted or remote content."),
)

COMPILED_CODE_RULES = [
    (rule, re.compile(rule[4], re.IGNORECASE)) for rule in CODE_RULES
]
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_])"
)
IPV4_RE = re.compile(
    r"(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9.])"
)
RATE_LIMIT_RE = re.compile(
    r"rate.?limit|retry-after|x-ratelimit|ratelimit-|backoff|exponential.?backoff|too many requests|http.?429|token.?bucket|quota.?exceeded",
    re.IGNORECASE,
)
API_CLIENT_MARKERS = {
    "OkHttp": (r"okhttp3\.", r"Lokhttp3/", r"OkHttpClient"),
    "Retrofit": (r"retrofit2\.", r"Lretrofit2/", r"@GET", r"@POST"),
    "HttpURLConnection": (r"HttpURLConnection", r"openConnection\("),
    "java.net.URL": (r"Ljava/net/URL;", r"new URL\("),
    "Volley": (r"com\.android\.volley", r"Lcom/android/volley/"),
    "WebView": (r"android\.webkit\.WebView", r"Landroid/webkit/WebView;->loadUrl"),
    "Apache HttpClient": (r"org\.apache\.http", r"Lorg/apache/http/"),
    "Ktor": (r"io\.ktor\.client", r"Lio/ktor/client/"),
    "gRPC": (r"io\.grpc", r"Lio/grpc/"),
    "WebSocket": (r"WebSocket", r"newWebSocket"),
    "Cronet": (r"org\.chromium\.net", r"Lorg/chromium/net/"),
}
API_HEADER_RE = re.compile(
    r"(?i)\b(accept|accept-encoding|content-type|authorization|www-authenticate|"
    r"cookie|set-cookie|user-agent|origin|referer|if-none-match|etag|cache-control|"
    r"x-api-key|x-auth-token|x-request-id|retry-after|x-ratelimit-[a-z0-9-]+|"
    r"ratelimit-[a-z0-9-]+|x-[a-z0-9-]{2,60})\b"
)
SMALI_INVOKE_RE = re.compile(
    r"^\s*invoke-\S+\s+\{[^}]*\},\s*(L[^;]+;)->([^\s(]+)\(([^)]*)\)(\S+)"
)
API_INVOKE_OWNER_RE = re.compile(
    r"^L(?:okhttp3/|retrofit2/|java/net/|javax/net/|javax/ws/rs/|com/android/volley/|"
    r"org/apache/http/|io/ktor/|io/grpc/|org/chromium/net/|android/webkit/|"
    r"com/google/api/client/|com/squareup/okhttp/|com/loopj/android/http/)"
)
RETROFIT_ANNOTATION_RE = re.compile(
    r"\.annotation\s+\S+\s+Lretrofit2/http/(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS);"
)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _finding(
    rule_id: str,
    category: str,
    severity: str,
    title: str,
    message: str,
    path: str,
    line: int | None,
    snippet: str,
    confidence: float,
) -> dict[str, Any]:
    return {
        "analyzer": "apk-surface",
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "verification_state": "static_unverified",
        "title": title,
        "message": message,
        "evidence": {"path": path, "line": line, "snippet": snippet},
    }


def _android_attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(ANDROID_NS + name) or element.attrib.get(name)


def _parse_manifest(path: Path, relative: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Thin compat wrapper; the v2 engine lives in surface/manifest_v2.py."""
    return parse_manifest_v2(path, relative, findings)


def analyze_apk_surface(
    apktool_dir: str | Path,
    *,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Inspect decoded XML/Smali/resources and produce inventory plus static leads."""
    root = Path(apktool_dir).expanduser().resolve(strict=True)
    root = Path(os.fspath(root))
    if not root.is_dir():
        raise ValueError(f"Apktool output is not a directory: {root}")

    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []
    coverage = {
        "dex_semantic_analysis": "not_run",
        "manifest_and_components": "not_found",
        "permissions": "not_found",
        "network_security_config": "not_found",
        "endpoints_and_domains": "not_scanned",
        "smali_security_indicators": "not_scanned",
        "dependency_fingerprints": "not_scanned",
        "native_libraries": "not_found",
        "resource_inventory": "not_scanned",
        "runtime_behavior": "not_performed",
        "dynamic_network_testing": "not_performed",
    }
    tree = classify_decoded_tree(root)
    files = tree.files
    symlink_count = tree.symlink_count
    if symlink_count:
        diagnostics.append({
            "code": "symlink_entries_skipped",
            "message": f"Skipped {symlink_count} symlinked entries in decoded output.",
        })

    extensions = tree.extension_counts
    native_libraries = sorted(
        path.relative_to(root).as_posix() for path in files
        if path.suffix.lower() in {".so", ".a"}
    )
    smali_files = [path for path in files if path.suffix.lower() == ".smali"]
    resource_files = [
        path for path in files
        if path.relative_to(root).parts[:1] in {("res",), ("assets",)}
    ]
    if resource_files:
        coverage["resource_inventory"] = "success"
    manifest = next((path for path in files if path.name == "AndroidManifest.xml"), None)
    manifest_facts: dict[str, Any] = {"status": "not_found"}
    if manifest:
        coverage["manifest_and_components"] = "success"
        coverage["permissions"] = "success"
        manifest_facts = _parse_manifest(manifest, manifest.relative_to(root).as_posix(), findings)
        if manifest_facts.get("status") != "success":
            coverage["manifest_and_components"] = "failed"
            coverage["permissions"] = "failed"
            diagnostics.append({"code": "manifest_parse_failed", "message": str(manifest_facts.get("error"))})

    app = manifest_facts.get("application", {}) if isinstance(manifest_facts, dict) else {}
    config_ref = app.get("network_security_config") if isinstance(app, dict) else None
    if config_ref:
        config_name = config_ref.rsplit("/", 1)[-1]
        config_path = next((p for p in files if p.name == config_name + ".xml"), None)
        if config_path:
            nsc = parse_network_security_config(config_path, config_path.relative_to(root).as_posix())
            coverage["network_security_config"] = (
                "success" if nsc["status"] == "parsed" else "failed"
            )
            findings.extend(nsc["findings"])
            manifest_facts.setdefault("network_security_config_facts", nsc["facts"])
            if nsc["status"] != "parsed":
                diagnostics.append({
                    "code": "network_config_parse_failed",
                    "message": f"{config_path}: {nsc.get('error')}",
                })
        else:
            coverage["network_security_config"] = "referenced_but_not_found"
    elif manifest_facts.get("status") == "success":
        coverage["network_security_config"] = "not_configured"

    # Backup-rules resolution (S3): same pattern as the NSC reference above.
    backup_facts: dict[str, Any] = {}
    for rule_key in ("full_backup_content", "data_extraction_rules"):
        rule_ref = app.get(rule_key) if isinstance(app, dict) else None
        if not rule_ref:
            continue
        rule_name = rule_ref.rsplit("/", 1)[-1]
        rule_path = next(
            (p for p in files if p.name == rule_name or p.name == rule_name + ".xml"),
            None,
        )
        if rule_path is None:
            backup_facts[rule_key] = {
                "reference": rule_ref, "status": "referenced_but_not_found",
            }
            continue
        parsed = parse_backup_rules(rule_path, rule_path.relative_to(root).as_posix())
        backup_facts[rule_key] = parsed
        for entry in parsed.get("entries", []):
            if entry.get("domain") in {"external", "file", "database", "sharedpref"} and entry.get("action") == "include":
                findings.append(_finding(
                    "backup_include_data_domain", "data_storage", "medium",
                    f"Backup rule includes data domain: {entry.get('domain')}",
                    "Backup rules explicitly include a private data domain; "
                    "review against the sensitivity of stored data.",
                    parsed["reference"], None, entry.get("path") or entry.get("domain"), 0.85,
                ))
    if backup_facts:
        manifest_facts["backup_rules"] = backup_facts
        coverage["backup_rules"] = "success"

    dependency_evidence: dict[str, list[str]] = {name: [] for name in DEPENDENCY_MARKERS}
    api_clients: dict[str, list[dict[str, Any]]] = {name: [] for name in API_CLIENT_MARKERS}
    api_call_sites: list[dict[str, Any]] = []
    api_endpoints: dict[str, dict[str, Any]] = {}
    api_routes: dict[str, dict[str, Any]] = {}
    api_headers: dict[str, list[dict[str, Any]]] = {}
    rate_limit_indicators: list[dict[str, Any]] = []
    scanned_text_bytes = 0
    code_scanned = 0
    scannable_total = sum(1 for item in files if item.suffix.lower() in TEXT_SUFFIXES)
    scan_started = last_heartbeat = time.monotonic()
    files_seen = 0
    _emit_progress(
        progress,
        f"[Surface] Scanning {scannable_total:,} text files ({len(smali_files):,} smali) for endpoints, routes and indicators",
    )
    sweep = SweepState(DEPENDENCY_MARKERS)
    sweep.api_clients = {name: [] for name in API_CLIENT_MARKERS}
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        files_seen += 1
        if time.monotonic() - last_heartbeat >= 2:
            last_heartbeat = time.monotonic()
            _emit_progress(
                progress,
                f"[Surface] scanning - {files_seen:,}/{scannable_total:,} files, "
                f"{int(last_heartbeat - scan_started)}s elapsed, "
                f"{len(sweep.api_endpoints):,} endpoints, {len(sweep.findings):,} findings",
            )
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            diagnostics.append({"code": "text_read_failed", "message": f"{relative}: {exc}"})
            continue
        scanned_text_bytes += path.stat().st_size
        code_scanned += 1
        coverage["endpoints_and_domains"] = "success"
        if path.suffix.lower() == ".smali":
            coverage["smali_security_indicators"] = "success"
        sweep.sweep_text(
            relative=relative,
            path=path,
            text=text,
            code_rules=COMPILED_CODE_RULES,
            api_client_markers=API_CLIENT_MARKERS,
            api_invoke_owner_re=API_INVOKE_OWNER_RE,
            smali_invoke_re=SMALI_INVOKE_RE,
            header_re=API_HEADER_RE,
            rate_limit_re=RATE_LIMIT_RE,
            dependency_markers=DEPENDENCY_MARKERS,
            emit=lambda message: None,
        )
    findings.extend(sweep.findings)
    dependency_evidence = sweep.dependency_evidence
    api_endpoints = sweep.api_endpoints
    api_routes = sweep.api_routes
    api_call_sites = sweep.api_call_sites
    api_clients = sweep.api_clients
    api_headers = sweep.api_headers
    rate_limit_indicators = sweep.rate_limit_indicators

    if smali_files and coverage["smali_security_indicators"] != "success":
        coverage["smali_security_indicators"] = "partial"
    if not smali_files:
        coverage["smali_security_indicators"] = "not_found"
    coverage["dependency_fingerprints"] = "success" if code_scanned else "not_scanned"
    coverage["native_libraries"] = "inventory_only" if native_libraries else "not_found"
    partial_diagnostics = {
        "symlink_entries_skipped", "text_file_limit", "text_read_failed",
        "manifest_parse_failed", "network_config_parse_failed",
        "network_config_referenced_not_found",
        "finding_limit",
    }
    if symlink_count or any(item["code"] in partial_diagnostics for item in diagnostics):
        for area in ("endpoints_and_domains", "smali_security_indicators", "dependency_fingerprints"):
            if coverage[area] == "success":
                coverage[area] = "partial"

    for endpoint, metadata in sorted(api_endpoints.items()):
        first = metadata["evidence"][0] if metadata["evidence"] else {}
        nearby_limit_signals = [
            signal for signal in rate_limit_indicators
            if signal["path"] == first.get("path")
            and first.get("line") is not None
            and abs(signal["line"] - first["line"]) <= 30
        ]
        metadata["nearby_rate_limit_indicators"] = nearby_limit_signals
        metadata["client_rate_limit_status"] = (
            "indicators_near_endpoint" if nearby_limit_signals
            else "no_nearby_client_indicator_found"
        )
        findings.append(_finding(
            "api_endpoint_inventory", "api_inventory", "info",
            f"API/network endpoint candidate: {endpoint}",
            f"String occurrence count: {metadata['occurrences']}. This endpoint was discovered statically; no request was sent.",
            str(first.get("path", "")), first.get("line"), endpoint, 0.99,
        ))
    for route, metadata in sorted(api_routes.items()):
        first = metadata["evidence"][0] if metadata["evidence"] else {}
        findings.append(_finding(
            "api_route_inventory", "api_inventory", "info",
            f"API route candidate: {metadata['http_method'] or 'METHOD UNKNOWN'} {route}",
            f"Route occurrence count: {metadata['occurrences']}. HTTP behavior was not exercised.",
            str(first.get("path", "")), first.get("line"), route, 0.88,
        ))
    dependencies = [
        {"name": name, "evidence_paths": sorted(set(paths))}
        for name, paths in sorted(dependency_evidence.items()) if paths
    ]
    return {
        "schema_version": 1,
        "analyzer": {"id": "apk-surface", "version": "0.2.0"},
        "status": (
            "success"
            if manifest_facts.get("status") == "success"
            and not any(item["code"] in partial_diagnostics for item in diagnostics)
            else "partial"
        ),
        "coverage": coverage,
        "manifest": manifest_facts,
        "inventory": {
            "file_count": len(files),
            "text_files_scanned": code_scanned,
            "text_bytes_scanned": scanned_text_bytes,
            "extension_counts": dict(sorted(extensions.items())),
            "classification": tree.summary(),
            "smali_file_count": len(smali_files),
            "resource_and_asset_file_count": len(resource_files),
            "resource_and_asset_paths": [path.relative_to(root).as_posix() for path in resource_files],
            "native_libraries": native_libraries,
            "dependencies": dependencies,
            "endpoints": [metadata for _value, metadata in sorted(api_endpoints.items())],
            "api_routes": [metadata for _route, metadata in sorted(api_routes.items())],
            "api_call_sites": api_call_sites,
            "api_clients": [
                {"name": name, "call_sites": calls, "call_site_count": len(calls)}
                for name, calls in sorted(api_clients.items()) if calls
            ],
            "api_headers": [
                {"name": name, "evidence": locations}
                for name, locations in sorted(api_headers.items())
            ],
            "rate_limit_indicators": rate_limit_indicators,
            "server_rate_limit_assessment": {
                "status": "not_determined_from_static_apk",
                "meaning": "Client-side strings or retry code cannot establish a server-side API quota or rate limit.",
                "client_side_indicators_found": bool(rate_limit_indicators),
            },
        },
        "findings": findings,
        "diagnostics": diagnostics,
        "limitations": [
            "Static indicators require analyst review and do not prove exploitability or runtime behavior.",
            "Reflection, obfuscation, native code, dynamically downloaded code, and unsupported file formats can limit visibility.",
            "No APK code was executed and no discovered endpoint was contacted.",
            "Runtime permissions, network traffic, backend behavior, and device-specific behavior were not tested.",
        ],
        "metrics": {
            "finding_count": len(findings),
            "endpoint_count": len(api_endpoints),
            "api_route_count": len(api_routes),
            "api_call_site_count": len(api_call_sites),
            "api_client_library_evidence_count": sum(len(items) for items in api_clients.values()),
            "rate_limit_indicator_count": len(rate_limit_indicators),
            "dependency_fingerprint_count": len(dependencies),
            "native_library_count": len(native_libraries),
        },
    }


def _emit_progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is None:
        return
    try:
        progress(message)
    except OSError:
        return


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def run_static_surface_analysis(
    database,
    workspace: str | Path,
    *,
    run_id: str | None = None,
    force: bool = False,
    dex_timeout_seconds: int = 1800,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run surface analysis for every eligible APK in a run and persist per-APK output."""
    root = Path(workspace).expanduser().resolve()
    results_root = root / "results"
    if results_root.is_symlink():
        raise ValueError("Results directory must not be a symlink.")
    results_root.mkdir(parents=True, exist_ok=True)
    results_root = results_root.resolve(strict=True)
    results_root.relative_to(root)

    marker_path = None
    if run_id is not None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", run_id):
            raise ValueError("Run ID contains invalid characters.")
        marker_dir = results_root / "runs" / run_id
        if any(part.is_symlink() for part in (results_root / "runs", marker_dir, marker_dir / "static-analysis-run.json")):
            raise ValueError("Static-analysis run marker path contains a symlink.")
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker_dir.resolve(strict=True).relative_to(results_root)
        marker_path = marker_dir / "static-analysis-run.json"

    def marker_refresh(status: str, eligible: int, completed: int, failed: int,
                       skipped: int, partial: int, finding_count: int,
                       artifacts: list[dict[str, Any]]) -> None:
        if marker_path is not None:
            _atomic_write_json(marker_path, {
                "schema_version": 1,
                "run_id": run_id,
                "status": status,
                "eligible": eligible,
                "completed": completed,
                "partial": partial,
                "failed": failed,
                "skipped": skipped,
                "finding_count": finding_count,
                "artifacts": artifacts,
            })
    marker_refresh("running", 0, 0, 0, 0, 0, 0, [])

    history = database.read_download_history()
    statuses = database.read_processing_status()
    if run_id is None:
        selected_rows = history
    else:
        selected_rows = []
        history_by_hash = {
            row.get("sha256", "").lower(): row for row in history if row.get("sha256")
        }
        for selected in database.read_manifest(run_id):
            acquired = history_by_hash.get(selected.get("sha256", "").lower())
            if (
                acquired is not None
                and acquired.get("run_id") == run_id
                and acquired.get("package_id") == selected.get("package_id")
                and str(acquired.get("version_code", "")) == str(selected.get("version_code", ""))
                and acquired.get("source") == selected.get("source")
            ):
                selected_rows.append(acquired)

    eligible = [
        row for row in selected_rows
        if statuses.get(row.get("sha256", "").lower(), {}).get("apktool_status")
        in {"success", "partial"}
    ]
    summary: dict[str, Any] = {
        "run_id": run_id,
        "eligible": len(eligible),
        "completed": 0,
        "failed": 0,
        "partial": 0,
        "skipped": len(selected_rows) - len(eligible),
        "finding_count": 0,
        "artifacts": [],
    }
    for index, row in enumerate(eligible, start=1):
        package_id = row.get("package_id", "")
        version_code = str(row.get("version_code", ""))
        digest = row.get("sha256", "").lower()
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id) or not version_code.isdigit():
            summary["failed"] += 1
            summary["artifacts"].append({
                "package_id": package_id, "version_code": version_code,
                "sha256": digest, "status": "failed",
                "error": "Malformed package identity in acquisition history.",
            })
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            summary["failed"] += 1
            summary["artifacts"].append({
                "package_id": package_id, "version_code": version_code,
                "sha256": digest, "status": "failed",
                "error": "Malformed SHA-256 in acquisition history.",
            })
            continue
        output_root = results_root / package_id / version_code / digest
        decoded = output_root / "apktool"
        target = output_root / "static-analysis.json"
        package_root = results_root / package_id
        version_root = package_root / version_code
        if any(path.is_symlink() for path in (package_root, version_root, output_root, decoded, target)):
            summary["failed"] += 1
            summary["artifacts"].append({
                "package_id": package_id, "version_code": version_code,
                "sha256": digest, "status": "failed",
                "error": "Refusing symlinked static-analysis path.",
            })
            continue
        if not decoded.is_dir():
            summary["skipped"] += 1
            continue
        if not force and target.is_file():
            try:
                prior = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prior = {}
            prior_dex = prior.get("dex_analysis") if isinstance(prior, dict) else None
            prior_analyzer = prior.get("analyzer", {}) if isinstance(prior, dict) else {}
            if (
                isinstance(prior, dict)
                and prior.get("status") in {"success", "partial"}
                and isinstance(prior_analyzer, dict)
                and prior_analyzer.get("version") == "0.2.0"
                and isinstance(prior_dex, dict)
                and prior_dex.get("status") in {"success", "partial"}
            ):
                summary["skipped"] += 1
                summary["finding_count"] += len(prior.get("findings", []))
                summary["artifacts"].append({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, "status": "skipped_reused",
                    "path": str(target), "finding_count": len(prior.get("findings", [])),
                })
                continue
        if progress:
            progress(f"[surface {index}/{len(eligible)}] Inspecting {package_id} v{version_code}")
        try:
            result = analyze_apk_surface(decoded, progress=progress)
            source_value = row.get("local_path", "")
            source_candidate = Path(source_value).expanduser()
            downloads_root = root / "downloads"
            if not source_value or source_candidate.is_symlink() or downloads_root.is_symlink():
                raise ValueError("Original acquired APK path is missing or symlinked.")
            source_apk = source_candidate.resolve(strict=True)
            source_apk.relative_to(downloads_root.resolve(strict=True))
            if not source_apk.is_file() or source_apk.suffix.lower() != ".apk":
                raise ValueError("Original acquired artifact is not a regular APK file.")
            expected_size = int(row.get("size") or 0)
            hash_obj = hashlib.sha256()
            actual_size = 0
            hash_started = time.monotonic()
            last_hash_beat = hash_started
            with source_apk.open("rb") as source_handle:
                for chunk_index, chunk in enumerate(
                    iter(lambda: source_handle.read(1024 * 1024), b""), start=1
                ):
                    hash_obj.update(chunk)
                    actual_size += len(chunk)
                    now = time.monotonic()
                    if now - last_hash_beat >= 2:
                        last_hash_beat = now
                        _emit_progress(
                            progress,
                            f"  hashing base.apk chunk {chunk_index} "
                            f"({actual_size:,} bytes; {int(now - hash_started)}s)",
                        )
            if hash_obj.hexdigest() != digest or (expected_size and actual_size != expected_size):
                raise ValueError(
                    "Original APK changed after acquisition; refusing DEX analysis "
                    "against bytes that no longer match the manifest."
                )
            _emit_progress(
                progress,
                f"  Source APK integrity rechecked: SHA-256 matches ({actual_size:,} bytes)",
            )
            _emit_progress(
                progress,
                f"  [Androguard] Parsing DEX, method references and API usage for {package_id}",
            )
            dex_result = analyze_apk_dex(
                source_apk,
                timeout_seconds=dex_timeout_seconds,
                progress=progress,
            )
            result["dex_analysis"] = dex_result
            result["coverage"]["dex_semantic_analysis"] = dex_result.get("status", "failed")
            if dex_result.get("status") != "success":
                result["status"] = "partial"
                result.setdefault("diagnostics", []).extend(dex_result.get("diagnostics", []))
                result.setdefault("limitations", []).extend(dex_result.get("limitations", []))
            # Original-APK zip inventory (Appendix C): every archive member
            # is mapped regardless of decode success; nested containers are
            # named. Never silently skipped: failures are recorded.
            try:
                result["apk_inventory"] = inventory_apk_zip(source_apk)
                result["coverage"]["apk_zip_inventory"] = "success"
            except (OSError, zipfile.BadZipFile) as exc:
                result["coverage"]["apk_zip_inventory"] = "failed"
                result.setdefault("diagnostics", []).append({
                    "code": "apk_inventory_failed",
                    "message": f"{type(exc).__name__}: {exc}",
                })
                result["status"] = "partial"
            result["artifact"] = {
                "package_id": package_id, "version_code": version_code,
                "sha256": digest, "source_apk": str(source_apk),
            }
            _atomic_write_json(target, result)
            count = len(result.get("findings", []))
            summary["completed"] += 1
            if result.get("status") != "success":
                summary["partial"] += 1
            summary["finding_count"] += count
            summary["artifacts"].append({
                "package_id": package_id, "version_code": version_code,
                "sha256": digest, "status": result["status"],
                "path": str(target), "finding_count": count,
                "dex_metrics": dex_result.get("metrics", {}),
                "coverage": result.get("coverage", {}),
            })
            _emit_progress(
                progress,
                f"  Complete: {count} static indicators; "
                f"{dex_result.get('metrics', {}).get('external_methods_referenced', 0)} "
                f"external DEX API references; report saved to {target}",
            )
        except (OSError, ValueError, RuntimeError) as exc:
            summary["failed"] += 1
            failure = {
                "schema_version": 1,
                "analyzer": {"id": "apk-surface", "version": "0.2.0"},
                "status": "failed",
                "artifact": {
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, "source_apk": row.get("local_path", ""),
                },
                "coverage": {},
                "findings": [],
                "diagnostics": [{"code": "surface_analysis_failed", "message": f"{type(exc).__name__}: {exc}"}],
                "limitations": ["Static analysis did not complete for this artifact."],
            }
            _atomic_write_json(target, failure)
            summary["artifacts"].append({
                "package_id": package_id, "version_code": version_code,
                "sha256": digest, "status": "failed", "path": str(target),
                "error": str(exc),
            })
            _emit_progress(progress, f"  FAILED: {package_id}: {exc}")
        # Always-alive marker: refresh after EVERY artifact so a crashed run
        # leaves an honest mid-state (observability + crash forensics).
        marker_refresh(
            "running",
            summary["eligible"], summary["completed"], summary["failed"],
            summary["skipped"], summary["partial"], summary["finding_count"],
            summary["artifacts"],
        )
    if marker_path is not None:
        marker_status = (
            "failed" if summary["failed"]
            else "partial" if summary["skipped"] or summary["partial"]
            else "success"
        )
        marker_refresh(
            marker_status,
            summary["eligible"], summary["completed"], summary["failed"],
            summary["skipped"], summary["partial"], summary["finding_count"],
            summary["artifacts"],
        )
    return summary
