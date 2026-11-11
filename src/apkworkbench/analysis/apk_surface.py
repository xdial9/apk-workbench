"""Broad, deterministic static surface inspection for Apktool-decoded APKs.

This analyzer reports evidence-backed static indicators and inventories. It does
not execute APK code, contact discovered endpoints, or claim runtime verification.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TEXT_SUFFIXES = {
    ".smali", ".xml", ".json", ".properties", ".yml", ".yaml", ".txt",
    ".js", ".html", ".htm", ".css", ".cfg", ".conf", ".ini", ".gradle",
    ".kt", ".java", ".md", ".plist", ".csv",
}
MAX_TEXT_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_TEXT_BYTES = 512 * 1024 * 1024
MAX_FINDINGS = 100_000

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

URL_RE = re.compile(r"""https?://[^\s"'<>\\]+""", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_])"
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
    facts: dict[str, Any] = {
        "package": None, "version_code": None, "version_name": None,
        "min_sdk": None, "target_sdk": None, "permissions": [],
        "application": {}, "components": [],
    }
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", **facts}

    facts["package"] = root.attrib.get("package")
    facts["version_code"] = _android_attr(root, "versionCode")
    facts["version_name"] = _android_attr(root, "versionName")
    for element in root:
        tag = _local_name(element.tag)
        if tag == "uses-sdk":
            facts["min_sdk"] = _android_attr(element, "minSdkVersion")
            facts["target_sdk"] = _android_attr(element, "targetSdkVersion")
        elif tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            name = _android_attr(element, "name")
            if name:
                facts["permissions"].append(name)
                if name in SENSITIVE_PERMISSIONS:
                    findings.append(_finding(
                        "sensitive_permission", "permissions", "info",
                        f"Sensitive permission requested: {name}", 
                        "Permission request is an exposure indicator, not proof that the permission is used.",
                        relative, None, ET.tostring(element, encoding="unicode"), 0.99,
                    ))
        elif tag == "application":
            facts["application"] = {
                "debuggable": _android_attr(element, "debuggable"),
                "allow_backup": _android_attr(element, "allowBackup"),
                "uses_cleartext_traffic": _android_attr(element, "usesCleartextTraffic"),
                "network_security_config": _android_attr(element, "networkSecurityConfig"),
                "task_affinity": _android_attr(element, "taskAffinity"),
            }
            app = facts["application"]
            if app["debuggable"] == "true":
                findings.append(_finding(
                    "manifest_debuggable", "manifest", "high", "Application marked debuggable",
                    "The decoded manifest sets android:debuggable=true.",
                    relative, None, ET.tostring(element, encoding="unicode"), 0.99,
                ))
            if app["uses_cleartext_traffic"] == "true":
                findings.append(_finding(
                    "manifest_cleartext_traffic", "network_security", "high",
                    "Application explicitly permits cleartext traffic",
                    "The decoded manifest sets android:usesCleartextTraffic=true.",
                    relative, None, ET.tostring(element, encoding="unicode"), 0.99,
                ))
            for component in element:
                component_type = _local_name(component.tag)
                if component_type not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                    continue
                name = _android_attr(component, "name") or "(unnamed)"
                exported = _android_attr(component, "exported")
                has_intent_filter = any(_local_name(child.tag) == "intent-filter" for child in component)
                component_permission = _android_attr(component, "permission")
                entry = {
                    "type": component_type, "name": name, "exported": exported,
                    "has_intent_filter": has_intent_filter, "permission": component_permission,
                }
                facts["components"].append(entry)
                if exported == "true":
                    findings.append(_finding(
                        "exported_component", "components", "medium",
                        f"Exported Android component: {name}",
                        "Review externally reachable component behavior, permissions, input validation, and sensitive operations.",
                        relative, None, ET.tostring(component, encoding="unicode"), 0.94,
                    ))
                elif exported is None and has_intent_filter:
                    findings.append(_finding(
                        "component_export_default", "components", "info",
                        f"Component export behavior depends on platform/target SDK: {name}",
                        "android:exported is omitted while an intent filter exists; determine effective behavior for supported Android versions.",
                        relative, None, ET.tostring(component, encoding="unicode"), 0.83,
                    ))
    facts["permissions"] = sorted(set(facts["permissions"]))
    return {"status": "success", **facts}


def analyze_apk_surface(apktool_dir: str | Path) -> dict[str, Any]:
    """Inspect decoded XML/Smali/resources and produce inventory plus static leads."""
    root = Path(apktool_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Apktool output is not a directory: {root}")

    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []
    coverage = {
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
    files: list[Path] = []
    total_bytes = 0
    symlink_count = 0
    for current, directories, names in __import__("os").walk(root):
        base = Path(current)
        kept_dirs = []
        for name in directories:
            candidate = base / name
            if candidate.is_symlink():
                symlink_count += 1
            else:
                kept_dirs.append(name)
        directories[:] = kept_dirs
        for name in names:
            candidate = base / name
            if candidate.is_symlink() or not candidate.is_file():
                symlink_count += int(candidate.is_symlink())
                continue
            files.append(candidate)
    files.sort()
    if symlink_count:
        diagnostics.append({
            "code": "symlink_entries_skipped",
            "message": f"Skipped {symlink_count} symlinked entries in decoded output.",
        })

    extensions = Counter(path.suffix.lower() or "(no extension)" for path in files)
    native_libraries = sorted(
        path.relative_to(root).as_posix() for path in files
        if path.suffix.lower() in {".so", ".a"}
    )
    smali_files = [path for path in files if path.suffix.lower() == ".smali"]
    resource_files = [path for path in files if path.relative_to(root).parts[:1] in {("res",), ("assets",)}]
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
            try:
                config_root = ET.parse(config_path).getroot()
                coverage["network_security_config"] = "success"
                for node in config_root.iter():
                    if _local_name(node.tag) == "base-config" and node.attrib.get("cleartextTrafficPermitted") == "true":
                        findings.append(_finding(
                            "network_config_cleartext", "network_security", "high",
                            "Network security config permits cleartext traffic",
                            "A base-config explicitly permits cleartext traffic.",
                            config_path.relative_to(root).as_posix(), None,
                            ET.tostring(node, encoding="unicode"), 0.99,
                        ))
                    if _local_name(node.tag) == "debug-overrides":
                        findings.append(_finding(
                            "network_config_debug_overrides", "network_security", "medium",
                            "Network security config contains debug overrides",
                            "Review debug trust anchors and ensure they are not included in a production build.",
                            config_path.relative_to(root).as_posix(), None,
                            ET.tostring(node, encoding="unicode"), 0.92,
                        ))
            except (OSError, ET.ParseError) as exc:
                coverage["network_security_config"] = "failed"
                diagnostics.append({"code": "network_config_parse_failed", "message": f"{config_path}: {exc}"})
        else:
            coverage["network_security_config"] = "referenced_but_not_found"

    dependency_evidence: dict[str, list[str]] = {name: [] for name in DEPENDENCY_MARKERS}
    endpoints: dict[str, dict[str, Any]] = {}
    scanned_text_bytes = 0
    code_scanned = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_TEXT_FILE_BYTES or scanned_text_bytes + size > MAX_TOTAL_TEXT_BYTES:
                diagnostics.append({"code": "text_file_limit", "message": f"Skipped text scan due to size budget: {relative} ({size} bytes)."})
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            diagnostics.append({"code": "text_read_failed", "message": f"{relative}: {exc}"})
            continue
        scanned_text_bytes += size
        code_scanned += 1
        coverage["endpoints_and_domains"] = "success"
        coverage["resource_inventory"] = "success"
        if path.suffix.lower() == ".smali":
            coverage["smali_security_indicators"] = "success"
        lowered_path = relative.lower()
        for dependency, markers in DEPENDENCY_MARKERS.items():
            if any(marker.lower() in lowered_path or marker.lower() in text.lower() for marker in markers):
                dependency_evidence[dependency].append(relative)

        for match in URL_RE.finditer(text):
            value = match.group(0).rstrip(".,);]}:")
            if value:
                endpoints.setdefault(value, {"path": relative, "count": 0})
                endpoints[value]["count"] += 1

        if path.suffix.lower() in {".smali", ".xml", ".js", ".java", ".kt", ".json", ".properties", ".html", ".htm"}:
            for line_number, line in enumerate(text.splitlines(), start=1):
                for rule_id, category, severity, title, pattern, confidence, rationale in CODE_RULES:
                    if re.search(pattern, line, flags=re.IGNORECASE):
                        findings.append(_finding(
                            rule_id, category, severity, title, rationale,
                            relative, line_number, line, confidence,
                        ))
                        if len(findings) >= MAX_FINDINGS:
                            diagnostics.append({"code": "finding_limit", "message": f"Finding cap reached at {MAX_FINDINGS}."})
                            break
                if len(findings) >= MAX_FINDINGS:
                    break
        if len(findings) >= MAX_FINDINGS:
            break

    if smali_files and coverage["smali_security_indicators"] != "success":
        coverage["smali_security_indicators"] = "partial"
    if not smali_files:
        coverage["smali_security_indicators"] = "not_found"
    coverage["dependency_fingerprints"] = "success" if code_scanned else "not_scanned"
    coverage["native_libraries"] = "success" if native_libraries else "not_found"

    for endpoint, metadata in sorted(endpoints.items()):
        findings.append(_finding(
            "endpoint_inventory", "endpoints", "info",
            f"Network endpoint discovered: {endpoint}",
            f"Endpoint string appeared {metadata['count']} time(s); no network request was made.",
            metadata["path"], None, endpoint, 0.99,
        ))
    dependencies = [
        {"name": name, "evidence_paths": sorted(set(paths))}
        for name, paths in sorted(dependency_evidence.items()) if paths
    ]
    return {
        "schema_version": 1,
        "analyzer": {"id": "apk-surface", "version": "0.1.0"},
        "status": "success" if manifest_facts.get("status") == "success" else "partial",
        "coverage": coverage,
        "manifest": manifest_facts,
        "inventory": {
            "file_count": len(files),
            "text_files_scanned": code_scanned,
            "text_bytes_scanned": scanned_text_bytes,
            "extension_counts": dict(sorted(extensions.items())),
            "smali_file_count": len(smali_files),
            "resource_and_asset_file_count": len(resource_files),
            "native_libraries": native_libraries,
            "dependencies": dependencies,
            "endpoints": [
                {"value": value, **metadata}
                for value, metadata in sorted(endpoints.items())
            ],
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
            "endpoint_count": len(endpoints),
            "dependency_fingerprint_count": len(dependencies),
            "native_library_count": len(native_libraries),
        },
    }
