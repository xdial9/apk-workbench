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
from urllib.parse import urlsplit

from apkworkbench.analysis.androguard_dex import analyze_apk_dex, _analyze_dex_payloads
from apkworkbench.analysis.surface.classify import (
    TEXT_SUFFIXES,
    classify_decoded_tree,
    inventory_apk_zip,
)
from apkworkbench.analysis.surface.checkpoint import (
    Checkpoint,
    FactWriter,
    _atomic_write_bytes as _atomic_write_checkpoint_bytes,
)
from apkworkbench.analysis.surface.serialize import finalize_result
from apkworkbench.analysis.surface.handoff import deliver_prompts, write_handoff
from apkworkbench.analysis.surface.links import (
    build_entry_points,
    build_link_graph,
    write_links,
    write_trace_chains_to_dir,
)
from apkworkbench.analysis.surface.ledger import (
    build_file_ledger,
    summarize as summarize_file_ledger,
    write_file_ledger,
)
from apkworkbench.analysis.surface.sweep import SweepState
from apkworkbench.analysis.surface.deductions import (
    api_surface,
    packed_or_obfuscated,
    permission_mismatch,
    sdk_stack,
)
from apkworkbench.analysis.surface.facts import FactStore, package_root_histogram
from apkworkbench.analysis.surface.native import (
    MAX_EMBEDDED_BYTES_TOTAL,
    MAX_EMBEDDED_LIBRARIES,
    MAX_EMBEDDED_LIBRARY_BYTES,
    NativeMethodIndex,
    analyze_native,
    extract_embedded_code,
    extract_library_loads,
)
from apkworkbench.analysis.surface.manifest_v2 import (
    looks_like_key,
    parse_backup_rules,
    parse_manifest_v2,
    parse_network_security_config,
)
from apkworkbench.analysis.surface.identity import (
    identity_findings,
    parse_apk_identity,
)
from apkworkbench.analysis.surface.resources import (
    index_value_files,
    parse_resource_table,
)
from apkworkbench.analysis.surface.xml_assets import (
    collect_file_providers,
    collect_layouts,
)

ANALYZER_ID = "apk-surface"
ANALYZER_VERSION = "0.3.0"

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# ---- P7: Scale / bounded-memory limits -------------------------------------
# A single text file larger than this is streamed line-by-line instead of
# read_text()-ing the whole thing into memory (D15: size guard on per-file
# reads in the sweep loop). 50 MiB covers any plausible decoded asset/XML;
# anything bigger is streamed.
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024
# Sweep chunk size when streaming a large file: lines are accumulated into
# chunks of this size and fed to sweep_text with a line offset.
SWEEP_STREAM_CHUNK_LINES = 10_000
# Checkpoint every N files processed or M seconds elapsed (durability vs. fsync cost).
CHECKPOINT_EVERY_FILES = 2000
CHECKPOINT_EVERY_SECONDS = 15.0
# Shard part record count (mirrors surface/shards.py DEFAULT_PART_RECORDS).
SHARD_PART_RECORDS = 5_000

_DEX_LIST_FIELDS = (
    "class_model",
    "method_model",
    "external_method_references",
    "internal_call_graph",
    "dex_api_strings",
    "reflection_sites",
    "permission_api_usage",
)
_DEX_SUM_METRICS = (
    "dex_files",
    "classes",
    "internal_methods",
    "external_methods_referenced",
    "external_methods_without_callers",
    "internal_call_graph_edges",
    "dex_api_string_candidates",
    "permission_api_usage",
    "class_model_count",
    "method_model_count",
    "string_class_index_entries",
    "reflection_site_count",
)


def _merge_dex_analysis(
    primary: dict[str, Any] | None,
    additional: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if additional is None:
        return primary
    if primary is None:
        return additional

    primary_metrics = primary.setdefault("metrics", {})
    additional_metrics = additional.get("metrics", {})
    if not isinstance(primary_metrics, dict):
        primary_metrics = {}
        primary["metrics"] = primary_metrics
    if not isinstance(additional_metrics, dict):
        additional_metrics = {}
    dex_index_offset = primary_metrics.get("dex_files", 0)
    if not isinstance(dex_index_offset, int) or dex_index_offset < 0:
        dex_index_offset = 0

    def offset_record(record: dict[str, Any]) -> dict[str, Any]:
        updated = dict(record)
        for key in ("dex_index", "dex_class"):
            index = updated.get(key)
            if isinstance(index, int) and not isinstance(index, bool):
                updated[key] = index + dex_index_offset
        for key in ("call_sites", "references"):
            nested = updated.get(key)
            if isinstance(nested, list):
                updated[key] = [
                    offset_record(item) if isinstance(item, dict) else item
                    for item in nested
                ]
        return updated

    for key in _DEX_LIST_FIELDS:
        extra_records = additional.get(key)
        if not isinstance(extra_records, list):
            continue
        records = primary.setdefault(key, [])
        if not isinstance(records, list):
            records = []
            primary[key] = records
        records.extend(
            offset_record(item) if isinstance(item, dict) else item
            for item in extra_records
        )

    primary_index = primary.setdefault("string_class_index", {})
    extra_index = additional.get("string_class_index", {})
    if isinstance(primary_index, dict) and isinstance(extra_index, dict):
        for value, classes in extra_index.items():
            if not isinstance(classes, list):
                continue
            merged = set(primary_index.get(value, []))
            merged.update(classes)
            primary_index[value] = sorted(merged)

    for key in _DEX_SUM_METRICS:
        extra_count = additional_metrics.get(key, 0)
        if isinstance(extra_count, int) and not isinstance(extra_count, bool):
            primary_metrics[key] = primary_metrics.get(key, 0) + extra_count

    primary_coverage = primary.setdefault("coverage", {})
    extra_coverage = additional.get("coverage", {})
    if isinstance(primary_coverage, dict) and isinstance(extra_coverage, dict):
        for key, extra_status in extra_coverage.items():
            current_status = primary_coverage.get(key)
            if current_status is None or current_status in ("not_applicable", "not_run"):
                primary_coverage[key] = extra_status
            elif extra_status not in ("not_applicable", "not_run", current_status):
                primary_coverage[key] = "partial"

    for key in ("diagnostics", "limitations"):
        extra_items = additional.get(key)
        if isinstance(extra_items, list):
            primary.setdefault(key, []).extend(extra_items)

    primary_status = primary.get("status")
    additional_status = additional.get("status")
    if primary_status in (None, "success"):
        primary["status"] = additional_status or primary_status or "success"
    elif additional_status not in (None, "success", primary_status):
        primary["status"] = "partial"
    return primary


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

# ---- P5 D9 endpoint-rollup helpers ------------------------------------------
# Identifier-shaped path segments are normalised to "{id}" so one findings-
# layer entry covers one endpoint pattern instead of every near-duplicate URL
# (e.g. /v1/users/123 and /v1/users/456). The facts plane keeps every concrete
# occurrence unchanged; only the report-facing finding is grouped.
_PATH_PARAM_RE = re.compile(
    r"^(?:\d{1,16}|[0-9a-fA-F]{16,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
_CITATION_SAMPLE_LIMIT = 10


def _endpoint_pattern(endpoint: str) -> str:
    """Normalise path-identifier segments of an endpoint to '{id}'."""
    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        return endpoint
    if not parsed.scheme or not parsed.netloc:
        return endpoint
    netloc = parsed.hostname or parsed.netloc
    if parsed.port:
        netloc += f":{parsed.port}"
    segments = (parsed.path or "/").split("/")
    normalised = [
        "{id}" if _PATH_PARAM_RE.match(segment) else segment
        for segment in segments
    ]
    path = "/".join(normalised).rstrip("/")
    return f"{parsed.scheme.lower()}://{netloc}{path}"


def _path_pattern(route: str) -> str:
    """Normalise path-identifier segments of a route string."""
    segments = route.split("/")
    normalised = [
        "{id}" if _PATH_PARAM_RE.match(segment) else segment
        for segment in segments
    ]
    return "/".join(normalised)


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
    # ---- P5 detection breadth (docs/rules.md documents every id/false-positive) ----
    ("certificate_pinning_present", "network_security", "info",
     "Certificate pinning configuration referenced",
     r"CertificatePinner|setCertificatePinner|pin-set|sha256/[A-Za-z0-9+/=]{16,}", 0.85,
     "A pinning control appears to be configured. Verify which hosts are pinned and whether every client enforces it."),
    ("certificate_pinning_bypass", "network_security", "high",
     "Certificate pinning appears disabled or built empty",
     r"setCertificatePinner\s*\(\s*null\s*\)|certificatePinner\s*=\s*null|CertificatePinner\.Builder\s*\(\s*\)\s*\.build\s*\(\s*\)", 0.80,
     "A pinner is cleared or built empty. Confirm whether pinning is intentionally bypassed in this build."),
    ("keystore_credential_access", "cryptography", "medium",
     "Android keystore / credential API referenced",
     r"KeyStore\.getInstance|AndroidKeyStore|Ljava/security/KeyStore;|KeyGenParameterSpec", 0.80,
     "Key material is handled through a keystore API. Review key protection flags, user-authentication binding and export paths."),
    ("sql_string_concatenation", "data_storage", "high",
     "SQL statement built by string concatenation",
     r"""(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^;\n]{0,160}["']\s*\+|\+\s*["'][^"'\n]{0,60}(?:WHERE|FROM|VALUES|ORDER\s+BY|LIMIT)\b|String\.format\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)""", 0.78,
     "A SQL statement is assembled from literal and non-literal parts. Check whether untrusted input reaches the concatenated segment instead of a bound parameter."),
    ("path_traversal", "file_system", "medium",
     "Parent-directory path component present in a string literal",
     r"""["'][^"'\n]*\.\./(?:\.\./)*|%2e%2e%2f""", 0.70,
     "A relative parent-directory sequence is present. Confirm whether it is joined with untrusted input and whether canonicalization or an allow-list bounds the result."),
    ("intent_redirection", "components", "medium",
     "Intent read from a Parcelable extra",
     r"Landroid/content/Intent;->getParcelableExtra|getParcelableExtra\s*\(|getParcelableArrayListExtra\s*\(", 0.70,
     "A Parcelable extra is read. If that Parcelable is an Intent and is started/forwarded without validation, an external caller can redirect it."),
    ("overlay_window", "components", "high",
     "Overlay window type or permission referenced",
     r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|SYSTEM_ALERT_WINDOW", 0.85,
     "An overlay window capability is present. Review whether the overlay can sit above other apps and what it displays."),
    ("clipboard_access", "privacy", "medium",
     "Clipboard API referenced",
     r"ClipboardManager|getPrimaryClip|setPrimaryClip|Landroid/content/ClipboardManager;", 0.80,
     "Clipboard content may be read or written. Check whether sensitive data can be captured from, or leaked to, the clipboard."),
    ("accessibility_service", "components", "high",
     "Accessibility service surface referenced",
     r"AccessibilityService|BIND_ACCESSIBILITY_SERVICE|Landroid/accessibilityservice/AccessibilityService;", 0.85,
     "An accessibility service can observe and act on other apps' UI. Verify the service is declared, intended and restricted."),
    ("root_emulator_detection", "environment_checks", "info",
     "Root/emulator detection indicator present",
     r"Superuser\.apk|/system/xbin/su|/system/bin/su\b|test-keys|ro\.debuggable|ro\.kernel\.qemu|ro\.hardware\.goldfish|genymotion", 0.80,
     "Root or emulator checks are present. This is defensive-posture evidence, not a vulnerability; note which checks run and what changes when they fire."),
    ("exported_provider_risk", "components", "high",
     "Exported content provider with a query/insert surface",
     r"""Landroid/content/ContentResolver;->query\(|->insert\(Landroid/net/Uri;|->bulkInsert\(|->update\(Landroid/net/Uri;""", 0.80,
     "Code invokes ContentResolver query/insert/bulkInsert/update with a content:// URI. Pair this with the manifest's exported <provider> facts (exported_component) to determine whether any app that can reach the authority may query or insert. Review readPermission/writePermission, grantUriPermissions and path restrictions."),
    ("task_hijacking", "components", "medium",
     "Activity taskAffinity or singleTask launchMode may permit task hijacking",
     r"""android:taskAffinity\s*=\s*"[^"]+"|android:launchMode\s*=\s*"(?:singleTask|singleInstance)\"""", 0.75,
     "An activity sets taskAffinity or singleTask/singleInstance launch mode. An attacker activity with the same affinity can hijack the task; verify affinity matches the package name and that the launch mode is actually required."),
)

COMPILED_CODE_RULES = [
    (rule, re.compile(rule[4], re.IGNORECASE)) for rule in CODE_RULES
]
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
    offset: int | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"path": path, "line": line, "snippet": snippet}
    # Native evidence is byte-addressed; add the offset only when it exists so
    # every existing (text) finding keeps its exact evidence shape.
    if offset is not None:
        evidence["offset"] = offset
    return {
        "analyzer": "apk-surface",
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "verification_state": "static_unverified",
        "title": title,
        "message": message,
        "evidence": evidence,
    }


# ---- P7: streaming file reader for large text files (D15) ------------------


def _stream_sweep_file(
    sweep: SweepState,
    relative: str,
    path: Path,
    code_rules: list[tuple[tuple, re.Pattern[str]]],
    api_client_markers: dict[str, tuple[str, ...]],
    api_invoke_owner_re: re.Pattern[str],
    smali_invoke_re: re.Pattern[str],
    header_re: re.Pattern[str],
    rate_limit_re: re.Pattern[str],
    dependency_markers: dict[str, tuple[str, ...]],
    emit: Callable[[str], None],
) -> None:
    """Stream a large text file line-by-line into the sweep, in chunks.

    Reads ``path`` without loading it entirely into memory. Lines are
    accumulated into chunks of SWEEP_STREAM_CHUNK_LINES and fed to
    ``sweep_text`` with an adjusted line offset so evidence cites real
    file line numbers.  A file with no newlines (one giant line) is still
    read in bounded chunks by falling back to read_text for that line.
    """
    chunk: list[str] = []
    chunk_start_line = 1

    def flush_chunk() -> None:
        nonlocal chunk, chunk_start_line
        if not chunk:
            return
        chunk_text = "\n".join(chunk) + "\n"
        sweep.sweep_text(
            relative=relative,
            path=path,
            text=chunk_text,
            code_rules=code_rules,
            api_client_markers=api_client_markers,
            api_invoke_owner_re=api_invoke_owner_re,
            smali_invoke_re=smali_invoke_re,
            header_re=header_re,
            rate_limit_re=rate_limit_re,
            dependency_markers=dependency_markers,
            emit=emit,
        )
        chunk_start_line += len(chunk)
        chunk = []

    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                chunk.append(line.rstrip("\n"))
                if len(chunk) >= SWEEP_STREAM_CHUNK_LINES:
                    flush_chunk()
    except OSError:
        # Fall back to read_text if streaming fails mid-way.
        text = path.read_text(encoding="utf-8", errors="replace")
        sweep.sweep_text(
            relative=relative,
            path=path,
            text=text,
            code_rules=code_rules,
            api_client_markers=api_client_markers,
            api_invoke_owner_re=api_invoke_owner_re,
            smali_invoke_re=smali_invoke_re,
            header_re=header_re,
            rate_limit_re=rate_limit_re,
            dependency_markers=dependency_markers,
            emit=emit,
        )
        return
    flush_chunk()


def _android_attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(ANDROID_NS + name) or element.attrib.get(name)


def _parse_manifest(path: Path, relative: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Thin compat wrapper; the v2 engine lives in surface/manifest_v2.py."""
    return parse_manifest_v2(path, relative, findings)


def _save_sweep_checkpoint(
    checkpoint: Checkpoint,
    state_path: Path,
    *,
    stage: str,
    processed_files: set[str],
    sweep: SweepState,
    native_method_index: NativeMethodIndex,
    native_loads: list[dict[str, Any]],
    scanned_relatives: set[str],
    read_failures: dict[str, str],
    scanned_text_bytes: int,
    code_scanned: int,
    coverage: dict[str, str],
) -> None:
    """Persist accumulated sweep state atomically before advancing the checkpoint."""
    sorted_processed = sorted(processed_files)
    state_payload = {
        "stage": stage,
        "processed_files": sorted_processed,
        "dependency_evidence": sweep.dependency_evidence,
        "api_endpoints": sweep.api_endpoints,
        "endpoint_hosts": sorted(sweep.endpoint_hosts),
        "api_routes": sweep.api_routes,
        "api_call_sites": sweep.api_call_sites,
        "api_clients": sweep.api_clients,
        "api_headers": sweep.api_headers,
        "rate_limit_indicators": sweep.rate_limit_indicators,
        "decoded_strings": sweep.decoded_strings,
        "decoded_seen": sorted(sweep.decoded_seen),
        "resource_id_literals": sweep.resource_id_literals,
        "findings": sweep.findings,
        "native_methods_by_class": native_method_index._by_class,
        "native_loads": native_loads,
        "scanned_relatives": sorted(scanned_relatives),
        "read_failures": read_failures,
        "scanned_text_bytes": scanned_text_bytes,
        "code_scanned": code_scanned,
        "endpoints_and_domains": coverage.get("endpoints_and_domains"),
        "smali_security_indicators": coverage.get("smali_security_indicators"),
    }
    _atomic_write_checkpoint_bytes(
        state_path,
        json.dumps(state_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
    )
    checkpoint.save(stage, processed_files=sorted_processed)


def _load_sweep_checkpoint(
    checkpoint: Checkpoint,
    state_path: Path,
    sweep: SweepState,
    native_method_index: NativeMethodIndex,
    native_loads: list[dict[str, Any]],
    scanned_relatives: set[str],
    read_failures: dict[str, str],
    coverage: dict[str, str],
) -> tuple[set[str], int, int]:
    """Restore sweep state from checkpoint; returns (processed_files, scanned_bytes, code_scanned)."""
    loaded = checkpoint.load()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set(), 0, 0
    if not isinstance(state, dict):
        return set(), 0, 0

    # sweep_state.json is written atomically before checkpoint.save(); when it
    # carries processed_files, treat it as the authoritative source of truth so
    # a crash between the two writes never re-sweeps already-recorded files.
    has_state_files = "processed_files" in state
    if has_state_files:
        raw_files = state.get("processed_files")
    elif loaded is not None:
        raw_files = loaded.get("processed_files")
    else:
        return set(), 0, 0

    if not isinstance(raw_files, list) or not raw_files:
        return set(), 0, 0
    if not all(isinstance(item, str) for item in raw_files):
        return set(), 0, 0

    restored_files = set(raw_files)
    if has_state_files:
        checkpoint_files = loaded.get("processed_files") if loaded is not None else None
        if (
            not isinstance(checkpoint_files, list)
            or not all(isinstance(item, str) for item in checkpoint_files)
            or set(checkpoint_files) != restored_files
        ):
            stage = state.get("stage")
            if not isinstance(stage, str) or not stage:
                stage = str((loaded or {}).get("stage") or "sweep")
            checkpoint.save(stage, processed_files=sorted(restored_files))

    if isinstance(state.get("dependency_evidence"), dict):
        for key, paths in state["dependency_evidence"].items():
            if key in sweep.dependency_evidence and isinstance(paths, list):
                sweep.dependency_evidence[key] = list(paths)
    if isinstance(state.get("api_endpoints"), dict):
        sweep.api_endpoints = dict(state["api_endpoints"])
    if isinstance(state.get("endpoint_hosts"), list):
        sweep.endpoint_hosts = set(state["endpoint_hosts"])
    if isinstance(state.get("api_routes"), dict):
        sweep.api_routes = dict(state["api_routes"])
    if isinstance(state.get("api_call_sites"), list):
        sweep.api_call_sites = list(state["api_call_sites"])
    if isinstance(state.get("api_clients"), dict):
        for key, calls in state["api_clients"].items():
            if key in sweep.api_clients and isinstance(calls, list):
                sweep.api_clients[key] = list(calls)
    if isinstance(state.get("api_headers"), dict):
        sweep.api_headers = dict(state["api_headers"])
    if isinstance(state.get("rate_limit_indicators"), list):
        sweep.rate_limit_indicators = list(state["rate_limit_indicators"])
    if isinstance(state.get("decoded_strings"), list):
        sweep.decoded_strings = list(state["decoded_strings"])
    if isinstance(state.get("decoded_seen"), list):
        sweep.decoded_seen = set(state["decoded_seen"])
    if isinstance(state.get("resource_id_literals"), list):
        sweep.resource_id_literals = list(state["resource_id_literals"])
    if isinstance(state.get("findings"), list):
        sweep.findings = list(state["findings"])
    if isinstance(state.get("native_methods_by_class"), dict):
        native_method_index._by_class = dict(state["native_methods_by_class"])
    if isinstance(state.get("native_loads"), list):
        native_loads.extend(state["native_loads"])
    if isinstance(state.get("scanned_relatives"), list):
        scanned_relatives.update(state["scanned_relatives"])
    if isinstance(state.get("read_failures"), dict):
        read_failures.update(state["read_failures"])
    if isinstance(state.get("endpoints_and_domains"), str):
        coverage["endpoints_and_domains"] = state["endpoints_and_domains"]
    if isinstance(state.get("smali_security_indicators"), str):
        coverage["smali_security_indicators"] = state["smali_security_indicators"]

    scanned_text_bytes = int(state.get("scanned_text_bytes") or 0)
    code_scanned = int(state.get("code_scanned") or 0)
    return set(raw_files), scanned_text_bytes, code_scanned


def analyze_apk_surface(
    apktool_dir: str | Path,
    *,
    progress: Callable[[str], None] | None = None,
    tree_root: str = "apktool/",
    output_dir: str | Path | None = None,
    apk_path: str | Path | None = None,
    checkpoint_dir: str | Path | None = None,
    finalize: bool = True,
) -> dict[str, Any]:
    """Inspect decoded XML/Smali/resources and produce inventory plus static leads.

    ``output_dir`` (optional) is the surface output folder. It receives the
    ``files.jsonl`` coverage ledger, ``resources.jsonl``, ``facts_stream.jsonl``
    (when checkpointing), and, when a cap overflows, ``shards/`` +
    ``shards-index.json``. Both summaries always land in the result; the files
    are written only when a directory is supplied, so direct callers (tests) do
    not write into the evidence tree.

    ``apk_path`` (optional) is the original APK. It supplies the identity
    plane: signing schemes, certificates, ABIs and zip totals. Without it the
    identity coverage is reported as ``not_found`` rather than guessed.

    ``checkpoint_dir`` (optional) enables P7 crash-resume. A Checkpoint state
    file is written there after every CHECKPOINT_EVERY_FILES files, recording
    which text files have been swept along with accumulated sweep state. On
    restart, already-swept files are skipped so the run resumes from the
    checkpoint instead of file zero. Per-file results are streamed to
    ``facts_stream.jsonl`` in ``output_dir`` as they are produced.
    """
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
        "resource_model": "not_found",
        "resource_links": "not_applicable",
        "file_provider_paths": "not_found",
        "layout_inventory": "not_found",
        "apk_identity": "not_found",
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
    # Containers that can carry native code: packed .so files and plugin
    # APK/JAR/ZIP archives in assets or res/raw. content_kind is observed.
    native_containers = sorted(
        entry.relative for entry in tree.entries
        if entry.content_kind == "zip"
        and entry.suffix.lower() in {".zip", ".apk", ".jar", ".aar", ".so", ".a"}
    )
    smali_files = [path for path in files if path.suffix.lower() == ".smali"]
    resource_files = [
        path for path in files
        if path.relative_to(root).parts[:1] in {("res",), ("assets",)}
    ]
    if resource_files:
        # Counted, not parsed. This scanner does not decode resources.arsc,
        # layouts or drawables; reporting "success" here asserted work that
        # never happened and told the AI a gap was closed.
        coverage["resource_inventory"] = "counted_not_parsed"
    else:
        coverage["resource_inventory"] = "not_found"
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

    manifest_relative = next(
        (path.relative_to(root).as_posix() for path in files if path.name == "AndroidManifest.xml"),
        "AndroidManifest.xml",
    )

    # ---- P1: APK identity + signing (from the original APK bytes) ---------
    # The decoded tree cannot answer "who signed this". Without an APK the
    # coverage says not_found instead of guessing from the package name.
    identity: dict[str, Any] = {
        "status": "not_found", "schemes": [], "certificates": [], "abis": [],
    }
    if apk_path is not None:
        identity = parse_apk_identity(apk_path)
        coverage["apk_identity"] = {
            "success": "success",
            "unsigned": "success",   # determined, and reported as a finding
            "partial": "partial",
            "failed": "failed",
        }.get(str(identity.get("status")), "failed")
        findings.extend(identity_findings(identity, manifest_relative))
        diagnostics.extend(identity.get("diagnostics") or [])

    # ---- P2a: resource table (resources.arsc -> id/type/name/value) -------
    resource_model: dict[str, Any] = {"status": "not_found", "entry_count": 0}
    resource_index: dict[int, dict[str, Any]] = {}
    if apk_path is not None:
        value_files = index_value_files(root, files)
        resource_model, resource_index = _parse_resources_to_disk(
            apk_path, output_dir, value_files
        )
        coverage["resource_model"] = {
            "success": "success",
            "partial": "partial",
            "not_found": "not_found",
            "failed": "failed",
        }.get(str(resource_model.get("status")), "failed")
        if coverage["resource_model"] == "success" and resource_files:
            # The table is parsed, so the file-level statement is no longer
            # "counted but not parsed".
            coverage["resource_inventory"] = "parsed"
        diagnostics.extend(resource_model.get("diagnostics") or [])

    # ---- P2c: FileProvider roots + layout inventory -----------------------
    provider_facts: list[dict[str, Any]] = []
    layout_facts: list[dict[str, Any]] = []
    if manifest_facts.get("status") == "success":
        provider_facts, provider_findings, provider_diagnostics = collect_file_providers(
            manifest_facts.get("components") or [], root, files
        )
        findings.extend(provider_findings)
        diagnostics.extend(provider_diagnostics)
        if provider_diagnostics and provider_facts:
            coverage["file_provider_paths"] = "partial"
        elif provider_diagnostics:
            coverage["file_provider_paths"] = "failed"
        elif provider_facts:
            coverage["file_provider_paths"] = "success"
    layout_facts, layout_diagnostics = collect_layouts(root, files)
    diagnostics.extend(layout_diagnostics)
    if layout_diagnostics and layout_facts:
        coverage["layout_inventory"] = "partial"
    elif layout_diagnostics:
        coverage["layout_inventory"] = "failed"
    elif layout_facts:
        coverage["layout_inventory"] = "success"

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
    # Per-file coverage ledger inputs: what the sweep actually read, and what it
    # tried and could not. A text candidate in neither list is undecodable.
    scanned_relatives: set[str] = set()
    read_failures: dict[str, str] = {}
    scan_started = last_heartbeat = time.monotonic()
    files_seen = 0
    _emit_progress(
        progress,
        f"[Surface] Scanning {scannable_total:,} text files ({len(smali_files):,} smali) for endpoints, routes and indicators",
    )
    sweep = SweepState(DEPENDENCY_MARKERS)
    sweep.api_clients = {name: [] for name in API_CLIENT_MARKERS}
    # Native mapping inputs, collected in the same pass (no second smali read):
    # declared `native` methods join to Java_* exports; System.load calls join
    # to .so files. Both are only parsed when the file actually contains them.
    native_method_index = NativeMethodIndex()
    native_loads: list[dict[str, Any]] = []
    # DOMAIN filter needs the manifest package (com.example.smoke is not a domain).
    # Manifest is parsed above, so package is known before sweeping.
    if isinstance(manifest_facts, dict):
        pkg = manifest_facts.get("package")
        if isinstance(pkg, str) and pkg:
            sweep.manifest_package = pkg
    # Resource ids are only collected for packages the APK actually declares.
    if resource_model.get("packages"):
        parsed_ids = {
            int(str(item.get("id")), 16) for item in resource_model["packages"]
            if item.get("id")
        }
        if parsed_ids:
            sweep.resource_package_ids = parsed_ids
    # ---- P7: checkpoint + streaming setup ---------------------------------
    # Resumable sweep: a Checkpoint records which text files have been swept
    # alongside a sweep_state.json snapshot. On restart, already-swept files
    # are skipped without losing their accumulated endpoints/findings/native
    # declarations. Per-file progress is streamed to facts_stream.jsonl in
    # output_dir as files are processed.
    checkpoint: Checkpoint | None = None
    checkpoint_state_path: Path | None = None
    processed_files: set[str] = set()
    fact_stream: FactWriter | None = None
    if checkpoint_dir is not None:
        checkpoint = Checkpoint(checkpoint_dir)
        checkpoint_state_path = checkpoint.path.with_name("sweep_state.json")
        processed_files, scanned_text_bytes, code_scanned = _load_sweep_checkpoint(
            checkpoint,
            checkpoint_state_path,
            sweep,
            native_method_index,
            native_loads,
            scanned_relatives,
            read_failures,
            coverage,
        )
        files_seen = code_scanned
        if output_dir is not None:
            fact_stream = FactWriter(Path(output_dir) / "facts_stream.jsonl")
            fact_stream.__enter__()
    files_since_checkpoint = 0
    last_checkpoint_at = scan_started
    try:
        for path in files:
            relative = path.relative_to(root).as_posix()
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            # P7 resume: skip files already swept in a previous (crashed) run.
            if relative in processed_files:
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
            # D15: size guard — stream large files instead of read_text()ing them
            # whole into memory.  Smaller files use the original fast path.
            file_size = path.stat().st_size
            text: str | None = None
            if file_size > MAX_SINGLE_FILE_BYTES:
                _stream_sweep_file(
                    sweep, relative, path,
                    code_rules=COMPILED_CODE_RULES,
                    api_client_markers=API_CLIENT_MARKERS,
                    api_invoke_owner_re=API_INVOKE_OWNER_RE,
                    smali_invoke_re=SMALI_INVOKE_RE,
                    header_re=API_HEADER_RE,
                    rate_limit_re=RATE_LIMIT_RE,
                    dependency_markers=DEPENDENCY_MARKERS,
                    emit=lambda message: None,
                )
            else:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    read_failures[relative] = f"{type(exc).__name__}: {exc}"
                    diagnostics.append({"code": "text_read_failed", "message": f"{relative}: {exc}"})
                    continue
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
            scanned_relatives.add(relative)
            scanned_text_bytes += file_size
            code_scanned += 1
            coverage["endpoints_and_domains"] = "success"
            if path.suffix.lower() == ".smali":
                coverage["smali_security_indicators"] = "success"
                # Native mapping inputs, collected in the same pass (no second
                # smali read). Reuse `text` from the fast path above.
                if text is not None:
                    native_method_index.add_file(text, relative)
                    native_loads.extend(extract_library_loads(text, relative))
            # P7: stream per-file results to disk and checkpoint periodically.
            if fact_stream is not None:
                fact_stream.write({
                    "kind": "sweep_file",
                    "file": relative,
                    "size": file_size,
                    "endpoints_count": len(sweep.api_endpoints),
                    "findings_count": len(sweep.findings),
                })
            processed_files.add(relative)
            files_since_checkpoint += 1
            if (
                checkpoint is not None
                and checkpoint_state_path is not None
                and (
                    files_since_checkpoint >= CHECKPOINT_EVERY_FILES
                    or (
                        files_since_checkpoint > 0
                        and time.monotonic() - last_checkpoint_at >= CHECKPOINT_EVERY_SECONDS
                    )
                )
            ):
                _save_sweep_checkpoint(
                    checkpoint,
                    checkpoint_state_path,
                    stage="sweep",
                    processed_files=processed_files,
                    sweep=sweep,
                    native_method_index=native_method_index,
                    native_loads=native_loads,
                    scanned_relatives=scanned_relatives,
                    read_failures=read_failures,
                    scanned_text_bytes=scanned_text_bytes,
                    code_scanned=code_scanned,
                    coverage=coverage,
                )
                files_since_checkpoint = 0
                last_checkpoint_at = time.monotonic()
                if fact_stream is not None:
                    fact_stream.sync()
        # P7: final checkpoint — mark sweep complete. Keep the file so a later
        # restart can resume from it (crash-resume contract). The pipeline driver
        # may delete it once the artifact is fully processed.
        if checkpoint is not None and checkpoint_state_path is not None:
            _save_sweep_checkpoint(
                checkpoint,
                checkpoint_state_path,
                stage="sweep_done",
                processed_files=processed_files,
                sweep=sweep,
                native_method_index=native_method_index,
                native_loads=native_loads,
                scanned_relatives=scanned_relatives,
                read_failures=read_failures,
                scanned_text_bytes=scanned_text_bytes,
                code_scanned=code_scanned,
                coverage=coverage,
            )
    finally:
        if fact_stream is not None:
            fact_stream.close()
    # ---- Native analysis (G4 + crown jewel 5) ----
    # ELF parse -> exports/imports, JNI join to declared native methods, load
    # sites, streamed strings (ASCII + UTF-16LE), evidence-only findings. The
    # deduped string set still feeds the endpoint sweep so native URLs/domains
    # keep appearing in endpoints/facts exactly as before.
    native_analysis = analyze_native(
        root,
        native_libraries,
        native_method_index=native_method_index,
        library_loads=native_loads,
        containers=native_containers,
        progress=progress,
        shard_dir=output_dir,
    )
    findings.extend(native_analysis.findings)
    diagnostics.extend(native_analysis.diagnostics)
    for lib_rel, strings_text in native_analysis.strings_by_lib.items():
        if not strings_text:
            continue
        sweep.sweep_text(
            relative=lib_rel,
            path=root / lib_rel,
            text=strings_text,
            code_rules=COMPILED_CODE_RULES,
            api_client_markers=API_CLIENT_MARKERS,
            api_invoke_owner_re=API_INVOKE_OWNER_RE,
            smali_invoke_re=SMALI_INVOKE_RE,
            header_re=API_HEADER_RE,
            rate_limit_re=RATE_LIMIT_RE,
            dependency_markers=DEPENDENCY_MARKERS,
            emit=lambda message: None,
        )
    # Native strings were swept as text purely to reuse the endpoint rules;
    # rewrite their evidence from text lines to real file byte offsets.
    _retarget_native_evidence(sweep, findings, native_analysis.string_line_offsets)
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
    partial_diagnostics = {
        "symlink_entries_skipped", "text_read_failed",
        "manifest_parse_failed", "network_config_parse_failed",
        "network_config_referenced_not_found",
        "file_ledger_write_failed",
        "native_elf_parse_failed", "native_not_elf", "native_string_limit",
        "native_string_fact_limit", "native_finding_limit",
        "native_container_unreadable", "native_container_member_limit",
        "native_embedded_byte_limit", "native_embedded_library_limit",
        "native_container_member_unreadable",
        "code_container_unreadable", "code_container_member_limit",
        "code_container_depth_limit", "code_embedded_byte_limit",
        "code_container_member_unreadable",
        "code_standalone_dex_limit", "code_standalone_dex_read_failed",
    }
    if symlink_count or any(item["code"] in partial_diagnostics for item in diagnostics):
        for area in ("endpoints_and_domains", "smali_security_indicators",
                     "dependency_fingerprints", "dex_semantic_analysis"):
            if coverage.get(area) == "success":
                coverage[area] = "partial"

    # D9: findings-layer rollup. One finding per endpoint PATTERN (identifier
    # path segments normalised to {id}) instead of one per distinct endpoint
    # value, with occurrence_count + a bounded citation sample. The facts plane
    # below still receives every occurrence of every endpoint value: no data is
    # dropped, only the report-facing finding is grouped.
    endpoint_groups: dict[str, dict[str, Any]] = {}
    for endpoint, metadata in sorted(api_endpoints.items()):
        if not isinstance(metadata, dict):
            continue
        endpoint_evidence = metadata.get("evidence") or []
        first = (
            endpoint_evidence[0]
            if endpoint_evidence and isinstance(endpoint_evidence[0], dict)
            else {}
        )
        first_line = first.get("line")
        nearby_limit_signals = [
            signal for signal in rate_limit_indicators
            if isinstance(signal, dict)
            and signal.get("path") == first.get("path")
            and isinstance(first_line, int)
            and isinstance(signal.get("line"), int)
            and abs(signal["line"] - first_line) <= 30
        ]
        metadata["nearby_rate_limit_indicators"] = nearby_limit_signals
        metadata["client_rate_limit_status"] = (
            "indicators_near_endpoint" if nearby_limit_signals
            else "no_nearby_client_indicator_found"
        )
        pattern = _endpoint_pattern(endpoint)
        group = endpoint_groups.setdefault(pattern, {
            "endpoints": [], "occurrences": 0, "evidence": [], "first": first,
        })
        group["endpoints"].append(endpoint)
        group["occurrences"] += int(metadata.get("occurrences") or 0)
        group["evidence"].extend(
            ev for ev in endpoint_evidence if isinstance(ev, dict)
        )
    for pattern, group in sorted(endpoint_groups.items()):
        first = group["first"]
        evidence = group["evidence"]
        sample = evidence[:_CITATION_SAMPLE_LIMIT]
        finding = _finding(
            "api_endpoint_inventory", "api_inventory", "info",
            f"API/network endpoint pattern: {pattern}",
            (
                f"{group['occurrences']} string occurrence(s) across "
                f"{len(group['endpoints'])} distinct endpoint value(s) under this "
                f"pattern; {len(evidence)} citation(s) recorded "
                f"(sample of {len(sample)} in this finding). "
                "Discovered statically; no request was sent."
            ),
            str(first.get("path", "")), first.get("line"), pattern, 0.99,
            offset=first.get("offset"),
        )
        finding["endpoint_pattern"] = pattern
        finding["endpoints"] = sorted(set(group["endpoints"]))
        finding["endpoint_count"] = len(finding["endpoints"])
        finding["occurrence_count"] = group["occurrences"]
        finding["citation_count"] = len(evidence)
        finding["citation_sample"] = [
            {
                "path": item.get("path"),
                "line": item.get("line"),
                "offset": item.get("offset"),
            }
            for item in sample
        ]
        finding["citation_sample_truncated"] = len(evidence) > len(sample)
        findings.append(finding)
    route_groups: dict[tuple[str | None, str], dict[str, Any]] = {}
    for route, metadata in sorted(api_routes.items()):
        if not isinstance(metadata, dict):
            continue
        route_evidence = metadata.get("evidence") or []
        key = (metadata.get("http_method"), _path_pattern(route))
        group = route_groups.setdefault(key, {
            "routes": [], "occurrences": 0, "evidence": [], "first": None,
        })
        group["routes"].append(route)
        group["occurrences"] += int(metadata.get("occurrences") or 0)
        group["evidence"].extend(
            ev for ev in route_evidence if isinstance(ev, dict)
        )
        if group["first"] is None:
            group["first"] = (
                route_evidence[0]
                if route_evidence and isinstance(route_evidence[0], dict)
                else {}
            )
    for (method, pattern), group in sorted(
        route_groups.items(), key=lambda kv: (kv[0][0] or "", kv[0][1])
    ):
        first = group["first"] or {}
        evidence = group["evidence"]
        sample = evidence[:_CITATION_SAMPLE_LIMIT]
        finding = _finding(
            "api_route_inventory", "api_inventory", "info",
            f"API route pattern: {method or 'METHOD UNKNOWN'} {pattern}",
            (
                f"{group['occurrences']} occurrence(s) across "
                f"{len(group['routes'])} distinct route value(s) under this pattern; "
                f"{len(evidence)} citation(s) recorded "
                f"(sample of {len(sample)} in this finding). "
                "HTTP behavior was not exercised."
            ),
            str(first.get("path", "")), first.get("line"), pattern, 0.88,
            offset=first.get("offset"),
        )
        finding["route_pattern"] = pattern
        finding["http_method"] = method
        finding["routes"] = sorted(set(group["routes"]))
        finding["route_count"] = len(finding["routes"])
        finding["occurrence_count"] = group["occurrences"]
        finding["citation_count"] = len(evidence)
        finding["citation_sample"] = [
            {
                "path": item.get("path"),
                "line": item.get("line"),
                "offset": item.get("offset"),
            }
            for item in sample
        ]
        finding["citation_sample_truncated"] = len(evidence) > len(sample)
        findings.append(finding)
    dependencies = [
        {"name": name, "evidence_paths": sorted(set(paths))}
        for name, paths in sorted(dependency_evidence.items()) if paths
    ]

    # ---- S5: fingerprint fact store + deduction templates -----------------
    fact_store = FactStore()
    # ---- P1 identity facts ------------------------------------------------
    apk_cite = f"apk:{identity.get('source', '')}" if identity.get("source") else "apk:"
    for scheme in identity.get("schemes") or []:
        fact_store.add("apk_signing_scheme", scheme, evidence={"path": apk_cite})
    for certificate in identity.get("certificates") or []:
        fact_store.add(
            "apk_signing_certificate", certificate.get("sha256", ""),
            evidence={"path": apk_cite},
            extra={
                "subject": certificate.get("subject_text"),
                "issuer": certificate.get("issuer_text"),
                "scheme": certificate.get("scheme"),
                "serial": certificate.get("serial"),
                "not_before": certificate.get("not_before"),
                "not_after": certificate.get("not_after"),
                "self_issued": certificate.get("self_issued"),
                "min_sdk": certificate.get("min_sdk"),
                "max_sdk": certificate.get("max_sdk"),
            },
        )
    for abi in identity.get("abis") or []:
        fact_store.add("apk_abi", abi, evidence={"path": apk_cite})
    for entry in manifest_facts.get("uses_library", []) or []:
        if entry.get("name"):
            fact_store.add(
                "uses_library", entry["name"], evidence={"path": manifest_relative},
                extra={"required": entry.get("required")},
            )
    for entry in manifest_facts.get("uses_native_library", []) or []:
        if entry.get("name"):
            fact_store.add(
                "uses_native_library", entry["name"], evidence={"path": manifest_relative},
                extra={"required": entry.get("required")},
            )
    for fact in provider_facts + layout_facts:
        fact_store.add(
            fact["kind"], fact["value"],
            evidence=fact.get("evidence"), extra=fact.get("extra"),
        )
    # ---- P2b: resolve the resource ids the bytecode actually uses ---------
    resource_ids_resolved = 0
    resource_ids_unresolved = 0
    for literal in sweep.resource_id_literals:
        if not isinstance(literal, dict) or literal.get("id") is None:
            continue
        literal_id = literal["id"]
        value = f"{literal_id:#010x}"
        literal_path = literal.get("path")
        evidence = (
            {"path": literal_path, "line": literal.get("line")}
            if literal_path
            else None
        )
        entry = resource_index.get(literal_id)
        if entry is None:
            resource_ids_unresolved += 1
            fact_store.add(
                "resource_id_unresolved", value, evidence=evidence,
                extra={"reason": "not_in_resource_table"},
            )
            continue
        resource_ids_resolved += 1
        fact_store.add(
            "resource_id_used", value, evidence=evidence,
            extra={
                "type": entry.get("type"),
                "name": entry.get("name"),
                "resource_value": entry.get("value"),
                "config": entry.get("config"),
                "file": entry.get("file"),
            },
        )
    if sweep.resource_id_literals:
        coverage["resource_links"] = (
            "success" if resource_ids_unresolved == 0 else "partial"
        )
    for record in api_endpoints.values():
        if not isinstance(record, dict):
            continue
        # CAP-FREE + EVIDENCE-COMPLETE: was evidence[0] only (count=1 even when
        # occurrences=9). Add once per evidence so count == occurrences and
        # ALL path:line pairs reach the AI. Also: extra used key "kind" which
        # FactStore.add() overwrote the fact's own kind ("endpoint" -> "url"/
        # "domain_candidate"). Renamed to "endpoint_kind" so fact kind stays "endpoint".
        value = record.get("canonical") or record.get("value")
        if not value:
            continue
        extra = {
            "endpoint_kind": record.get("kind"), "host": record.get("host"),
            "host_class": record.get("host_class"), "flags": record.get("flags", []),
        }
        if record.get("evidence"):
            for ev in record["evidence"]:
                fact_store.add("endpoint", value, evidence=ev, extra=dict(extra))
        else:
            fact_store.add("endpoint", value, evidence=None, extra=dict(extra))
    for route, route_data in api_routes.items():
        if not isinstance(route_data, dict):
            continue
        route_value = f"{route_data.get('http_method') or '?'} {route}"
        if route_data.get("evidence"):
            for ev in route_data["evidence"]:
                fact_store.add("api_route", route_value, evidence=ev)
        else:
            fact_store.add("api_route", route_value, evidence=None)
    if isinstance(manifest_facts.get("deep_links"), list):
        for link in manifest_facts["deep_links"]:
            if not isinstance(link, dict) or not link.get("scheme"):
                continue
            fact_store.add(
                "deep_link",
                f"{link['scheme']}://{link.get('host', '')}{link.get('path', '')}",
                evidence={"path": manifest_relative}, extra={"component": link.get("component")},
            )
    for permission in manifest_facts.get("permissions", []) or []:
        fact_store.add("permission_requested", permission, evidence={"path": manifest_relative})
    for provider in manifest_facts.get("providers", []) or []:
        if not isinstance(provider, dict):
            continue
        for authority in provider.get("authorities") or []:
            fact_store.add("provider_authority", authority, evidence={"path": manifest_relative}, extra={
                "component": provider.get("name"),
            })
    for entry in manifest_facts.get("meta_data", []) or []:
        if (
            isinstance(entry, dict)
            and entry.get("name")
            and entry.get("value")
            and looks_like_key(entry["name"], entry["value"])
        ):
            fact_store.add("meta_data_key", f'{entry["name"]}={entry["value"]}', evidence={"path": manifest_relative})
    for item in sweep.decoded_strings:
        if not isinstance(item, dict) or item.get("decoded") is None:
            continue
        item_path = item.get("path")
        if item_path:
            item_evidence: dict[str, Any] | None = {
                "path": item_path,
                "line": item.get("line"),
            }
            if item.get("offset") is not None:
                item_evidence["offset"] = item["offset"]
        else:
            item_evidence = None
        fact_store.add(
            "decoded_string",
            item["decoded"],
            evidence=item_evidence,
            extra={
                "encoded": item.get("encoded"),
                "reveals": item.get("reveals", []),
            },
        )
    for dependency in dependencies:
        if dependency.get("evidence_paths"):
            for ev_path in dependency["evidence_paths"]:
                fact_store.add("dependency_sdk", dependency["name"], evidence={"path": ev_path})
        else:
            fact_store.add("dependency_sdk", dependency["name"], evidence=None)
    for library in native_libraries:
        fact_store.add("native_library", library, evidence={"path": library})
    for fact in native_analysis.facts:
        fact_store.add(
            fact["kind"], fact["value"],
            evidence=fact.get("evidence"), extra=fact.get("extra"),
        )

    histogram = package_root_histogram(tree.entries, manifest_facts.get("package"))
    smali_entries = [
        entry for entry in tree.entries if entry.suffix == ".smali"
    ]
    if len(smali_entries) >= 20:
        short_names = sum(
            1 for entry in smali_entries if len(entry.path.stem) <= 3
        )
        short_name_ratio = round(short_names / len(smali_entries), 3)
    else:
        short_name_ratio = None
    large_asset_blobs = sum(
        1 for entry in tree.entries
        if entry.relative.startswith("assets/")
        and entry.size_bytes > 1_000_000
        and (
            entry.content_kind in {"zip", "gzip"}
            or (entry.content_kind is None and entry.suffix not in TEXT_SUFFIXES)
        )
    )
    large_asset_blob_paths = sorted(
        entry.relative
        for entry in tree.entries
        if entry.relative.startswith("assets/")
        and entry.size_bytes > 1_000_000
        and (
            entry.content_kind in {"zip", "gzip"}
            or (entry.content_kind is None and entry.suffix not in TEXT_SUFFIXES)
        )
    )
    code_rule_hits = [
        finding["rule_id"]
        for finding in findings
        if isinstance(finding, dict) and finding.get("rule_id")
    ]
    short_name_smali_paths = sorted(
        entry.relative
        for entry in smali_entries
        if len(entry.path.stem) <= 3
    )
    deductions: list[dict[str, Any]] = []
    for deduction in (
        sdk_stack(fact_store, histogram),
        api_surface(fact_store, list(api_endpoints.values()), api_routes),
        *packed_or_obfuscated(
            fact_store, code_rule_hits, large_asset_blobs, short_name_ratio,
            findings=findings, large_asset_blob_paths=large_asset_blob_paths,
            short_name_smali_paths=short_name_smali_paths,
        ),
    ):
        if deduction is not None:
            deductions.append(deduction)
    deductions.sort(key=lambda item: item["id"])
    # Deduction facts now carry evidence from deductions.py directly. No post-hoc enrichment (re-adding would double-count).
    coverage.update(native_analysis.coverage)
    standalone_dex_payloads: list[tuple[bytes, str]] = []
    standalone_dex_skips: dict[str, str] = {}
    standalone_dex_bytes = 0
    standalone_dex_entries = [
        entry for entry in tree.entries if entry.content_kind == "dex"
    ]
    for entry in standalone_dex_entries:
        relative = entry.relative
        if (
            len(standalone_dex_payloads) >= MAX_EMBEDDED_LIBRARIES
            or entry.size_bytes > MAX_EMBEDDED_LIBRARY_BYTES
            or standalone_dex_bytes + entry.size_bytes > MAX_EMBEDDED_BYTES_TOTAL
        ):
            diagnostics.append({
                "code": "code_standalone_dex_limit",
                "message": (
                    f"{relative}: standalone DEX exceeds the bounded analysis "
                    f"budget ({entry.size_bytes} bytes; "
                    f"{MAX_EMBEDDED_LIBRARIES} files, "
                    f"{MAX_EMBEDDED_LIBRARY_BYTES} bytes per file, "
                    f"{MAX_EMBEDDED_BYTES_TOTAL} bytes total)"
                ),
            })
            standalone_dex_skips[relative] = "dex_analysis_limit"
            continue
        try:
            with entry.path.open("rb") as handle:
                payload = handle.read(MAX_EMBEDDED_LIBRARY_BYTES + 1)
        except OSError as exc:
            diagnostics.append({
                "code": "code_standalone_dex_read_failed",
                "message": f"{relative}: {type(exc).__name__}: {exc}",
            })
            standalone_dex_skips[relative] = "dex_read_failed"
            continue
        if len(payload) != entry.size_bytes or len(payload) > MAX_EMBEDDED_LIBRARY_BYTES:
            diagnostics.append({
                "code": "code_standalone_dex_read_failed",
                "message": (
                    f"{relative}: file size changed during bounded read "
                    f"(classified {entry.size_bytes} bytes, read {len(payload)})"
                ),
            })
            standalone_dex_skips[relative] = "dex_read_failed"
            continue
        standalone_dex_payloads.append((payload, relative))
        standalone_dex_bytes += len(payload)

    # ---- P0: per-file coverage ledger ------------------------------------
    # Every tree entry gets one record with a status and, when not checked, a
    # reason. Counts alone could not prove what was skipped; this can.
    native_skipped = {
        lib["path"]: (
            "native_not_elf_archive"
            if lib.get("reason") == "not_elf_archive"
            else "native_not_elf"
            if lib.get("state") == "not_elf"
            else "native_elf_parse_failed"
        )
        for lib in native_analysis.libraries
        if "!" not in lib["path"] and lib.get("state") in {"parse_failed", "not_elf"}
    }
    file_ledger = build_file_ledger(
        tree, scanned=scanned_relatives, read_failures=read_failures,
        dex_analyzed={
            citation for _payload, citation in standalone_dex_payloads
        },
        dex_skipped=standalone_dex_skips,
        native_skipped=native_skipped,
    )
    file_ledger_summary = summarize_file_ledger(file_ledger)
    if output_dir is not None:
        try:
            write_file_ledger(output_dir, file_ledger)
        except OSError as exc:
            diagnostics.append({
                "code": "file_ledger_write_failed",
                "message": f"{type(exc).__name__}: {exc}",
            })
            file_ledger_summary["written"] = False
        else:
            file_ledger_summary["written"] = True
    else:
        file_ledger_summary["written"] = False

    result = {
        "schema_version": 1,
        "analyzer": {"id": ANALYZER_ID, "version": ANALYZER_VERSION},
        "status": (
            "success"
            if manifest_facts.get("status") == "success"
            and not any(item["code"] in partial_diagnostics for item in diagnostics)
            else "partial"
        ),
        "coverage": coverage,
        "manifest": manifest_facts,
        "identity": identity,
        "facts": fact_store.export(),
        "deductions": deductions,
        "sdk_histogram": histogram,
        "inventory": {
            "file_count": len(files),
            "text_files_scanned": code_scanned,
            "text_bytes_scanned": scanned_text_bytes,
            "extension_counts": dict(sorted(extensions.items())),
            "classification": tree.summary(),
            "file_ledger": file_ledger_summary,
            "smali_file_count": len(smali_files),
            "resource_model": {
                "status": resource_model.get("status"),
                "entry_count": resource_model.get("entry_count", 0),
                "type_counts": resource_model.get("type_counts", {}),
                "packages": resource_model.get("packages", []),
                "string_pool_size": resource_model.get("string_pool_size", 0),
                "resources_jsonl": resource_model.get("resources_jsonl"),
            },
            "resource_and_asset_file_count": len(resource_files),
            "resource_and_asset_paths": [path.relative_to(root).as_posix() for path in resource_files],
            "native_libraries": native_libraries,
            "native_analysis": native_analysis.libraries,
            "jni_entries": native_analysis.jni_entries,
            "jni_unmapped": native_analysis.unmapped_entries,
            "native_library_loads": native_analysis.load_sites,
            "native_embedded_libraries": native_analysis.embedded_citations,
            "shards_index": "shards-index.json" if native_analysis.shard_index else None,
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
            "resource_id_references": len(sweep.resource_id_literals),
            "resource_ids_resolved": resource_ids_resolved,
            "resource_ids_unresolved": resource_ids_unresolved,
            "file_provider_root_count": len(provider_facts),
            "layout_count": sum(1 for item in layout_facts if item["kind"] == "layout"),
            "custom_view_count": sum(
                1 for item in layout_facts if item["kind"] == "custom_view"
            ),
            **native_analysis.metrics,
        },
    }

    # ---- P6: analyze standalone and container-nested DEX payloads ----------
    # Nested containers (.jar/.apk inside .zip) are recursed by
    # extract_embedded_code up to MAX_CONTAINER_DEPTH. Every extracted .dex is
    # fed to the DEX analyzer with container!member citations. Works whether or
    # not a source APK file is available.
    code_containers = sorted(
        entry.relative for entry in tree.entries
        if entry.content_kind == "zip"
        and entry.suffix.lower() in {".zip", ".apk", ".jar", ".aar"}
    )
    embedded_code = extract_embedded_code(
        root, code_containers,
        diagnostics=result.setdefault("diagnostics", []),
    )
    temp_paths: list[Path] = []
    try:
        embedded_dex = [
            item for item in embedded_code
            if item.member.lower().endswith(".dex")
        ]
        temp_paths.extend(item.path for item in embedded_code)
        dex_payloads = list(standalone_dex_payloads)
        dex_payloads.extend(
            (item.path.read_bytes(), item.citation) for item in embedded_dex
        )
        if dex_payloads:
            _emit_progress(
                progress,
                f"  [Androguard] Analyzing {len(dex_payloads)} standalone or embedded DEX payload(s)",
            )
            target_sdk = int(
                result.get("manifest", {}).get("target_sdk") or 0
            )
            embedded_result = _analyze_dex_payloads(
                dex_payloads, target_sdk=target_sdk
            )
            dex_result = _merge_dex_analysis(
                result.get("dex_analysis"), embedded_result
            )
            result["dex_analysis"] = dex_result
            if embedded_result.get("status") != "success":
                result["status"] = "partial"
            # Combine coverage: embedded DEX analysis only adds to what the
            # top-level APK analysis already established; never downgrade an
            # existing "success" to "not_applicable" just because no containers
            # were found. When both exist, the worse status wins.
            existing_coverage = result["coverage"].get("dex_semantic_analysis")
            embedded_status = embedded_result.get("status", "failed")
            if existing_coverage in (None, "not_run", "not_applicable") or (
                existing_coverage == "success" and embedded_status != "success"
            ):
                result["coverage"]["dex_semantic_analysis"] = embedded_status
        elif code_containers:
            # Containers exist but no extractable .dex members (all skipped by
            # caps). Coverage is partial, not a bare success — the container
            # scan produced a gap even if the top-level APK DEX was fine.
            existing = result["coverage"].get("dex_semantic_analysis")
            if existing in (None, "not_run", "not_applicable", "success"):
                result["coverage"]["dex_semantic_analysis"] = "partial"
        elif result["coverage"].get("dex_semantic_analysis") in (None, "not_run", "not_applicable"):
            # No containers at all: no embedded DEX to analyze.
            result["coverage"]["dex_semantic_analysis"] = "not_applicable"
    finally:
        for path in temp_paths:
            path.unlink(missing_ok=True)

    if standalone_dex_skips:
        if result["coverage"].get("dex_semantic_analysis") in (
            None, "not_run", "not_applicable", "success",
        ):
            result["coverage"]["dex_semantic_analysis"] = "partial"
        result["status"] = "partial"

    if finalize:
        return finalize_result(result, tree_root=tree_root)
    return result


def _retarget_native_evidence(
    sweep: SweepState,
    findings: list[dict[str, Any]],
    line_offsets: dict[str, list[int]],
) -> None:
    """Replace synthetic text line numbers with real byte offsets for .so evidence.

    Native strings are swept as newline-joined text so the endpoint/domain rules
    can run unchanged, but a line number inside a binary is a fabricated cite.
    Line N of the joined text is the Nth scanned string, whose true file offset
    is known, so the cite is retargeted to ``offset`` and the fake line removed.
    """

    def fix(item: Any) -> None:
        if not isinstance(item, dict):
            return
        relative = item.get("path")
        line = item.get("line")
        offsets = line_offsets.get(relative) if isinstance(relative, str) else None
        if not offsets or not isinstance(line, int) or line <= 0:
            return
        if line <= len(offsets):
            item["offset"] = offsets[line - 1]
        item.pop("line", None)

    for record in sweep.api_endpoints.values():
        for evidence in record.get("evidence", []):
            fix(evidence)
    for record in sweep.api_routes.values():
        for evidence in record.get("evidence", []):
            fix(evidence)
    for locations in sweep.api_headers.values():
        for evidence in locations:
            fix(evidence)
    for evidence in sweep.rate_limit_indicators:
        fix(evidence)
    for evidence in sweep.api_call_sites:
        fix(evidence)
    for evidence in sweep.decoded_strings:
        fix(evidence)
    for finding in findings:
        fix(finding.get("evidence"))


def _parse_resources_to_disk(
    apk_path: str | Path,
    output_dir: str | Path | None,
    value_files: dict[tuple[str, str], str] | None = None,
) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
    """Stream the resource table to resources.jsonl, or count it if no sink.

    The table can be hundreds of thousands of records, so it is written while
    it is parsed; static-analysis.json only carries the summary.
    """
    target: Path | None = None
    temporary: Path | None = None
    handle: Any = None
    try:
        if output_dir is not None:
            target = Path(output_dir) / "resources.jsonl"
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
            handle = temporary.open("w", encoding="utf-8")

            def sink(record: dict[str, Any]) -> None:
                handle.write(
                    json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    + "\n"
                )
        else:
            def sink(record: dict[str, Any]) -> None:
                # No output dir: the table is still parsed for its counts.
                return None

        id_index: dict[int, dict[str, Any]] = {}
        summary = parse_resource_table(
            apk_path, sink=sink, value_files=value_files, id_index=id_index
        )
        if handle is not None:
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            handle = None
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
            summary["resources_jsonl"] = "resources.jsonl"
        return summary, id_index
    except OSError as exc:
        return {
            "status": "failed",
            "entry_count": 0,
            "diagnostics": [{
                "code": "resource_table_write_failed",
                "message": f"{type(exc).__name__}: {exc}",
            }],
        }, {}
    finally:
        if handle is not None:
            handle.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _emit_progress(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is None:
        return
    try:
        progress(message)
    except OSError:
        return


NON_SERIALIZABLE_MARKER = "__non_serializable__"


def _non_serializable_marker(obj: Any) -> dict[str, Any]:
    """Replace one stray object with an explicit, greppable marker.

    A single leaked Androguard object used to abort a multi-hour run at the
    final write. The marker keeps the artifact loadable and names the type so
    the leak is still visible instead of silently dropped.
    """
    kind = f"{type(obj).__module__}.{type(obj).__qualname__}"
    try:
        preview = repr(obj)[:300]
    except Exception:  # pragma: no cover - a broken __repr__ must not crash
        preview = "<unrepresentable>"
    return {NON_SERIALIZABLE_MARKER: True, "type": kind, "repr": preview}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write ``payload`` as JSON; never raise on a stray object.

    Non-serializable values are replaced by ``NON_SERIALIZABLE_MARKER`` records
    and the payload is annotated (diagnostic + ``partial`` status) so the
    artifact stays honest. This is the last line of defence for long runs: a
    leaked third-party object must degrade the artifact, not destroy it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    markers: list[str] = []

    def _default(obj: Any) -> dict[str, Any]:
        marker = _non_serializable_marker(obj)
        markers.append(str(marker["type"]))
        return marker

    attempts = 0
    while True:
        attempts += 1
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                del markers[:]
                json.dump(
                    payload, handle, ensure_ascii=False, indent=2, default=_default
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if markers and attempts == 1:
                # Record the degradation inside the artifact, then rewrite it
                # once so the diagnostic is part of the published evidence.
                unique = sorted(set(markers))
                payload.setdefault("diagnostics", []).append({
                    "code": "non_serializable_value",
                    "message": (
                        f"{len(markers)} value(s) were not JSON serializable and "
                        f"were replaced with {NON_SERIALIZABLE_MARKER} markers: "
                        + ", ".join(unique[:10])
                    ),
                })
                if payload.get("status") == "success":
                    payload["status"] = "partial"
                continue
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            break
        finally:
            temporary.unlink(missing_ok=True)


def cross_apk_native_jni_match(
    results_root: Path,
    eligible_rows: list[dict[str, str]],
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Cross-APK native JNI matching (crown jewel 5).

    When .so files live in split APKs but smali `native` declarations live
    in the base APK (or another split), per-APK analysis cannot match them
    because `native_method_index` is built from that APK's smali only.
    This pass parses every .so file directly via parse_elf to find Java_*
    JNI exports, collects all smali `native` declarations from every APK,
    matches them across APK boundaries, and writes native_jni_entry facts
    back to each APK's surface/static-analysis.json.

    Returns a dict with matched/unmatched counts and per-artifact results.
    """
    from types import SimpleNamespace
    from apkworkbench.analysis.surface.native import (
        NativeMethodIndex,
        demangle_jni_symbol,
        _map_jni_symbol,
    )
    from apkworkbench.analysis.surface.native_elf import parse_elf

    # ---- Phase 1: Build combined NativeMethodIndex from ALL APKs' smali ----
    combined_index = NativeMethodIndex()
    smali_files = 0
    for row in eligible_rows:
        package_id = row.get("package_id", "")
        version_code = str(row.get("version_code", ""))
        digest = row.get("sha256", "").lower()
        decoded = results_root / package_id / version_code / digest / "apktool"
        if not decoded.is_dir():
            continue
        for smali_file in decoded.rglob("*.smali"):
            try:
                text = smali_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            relative = smali_file.relative_to(decoded).as_posix()
            combined_index.add_file(text, relative)
            smali_files += 1

    if smali_files == 0:
        return {"matched": 0, "unmatched": 0, "smali_files": 0, "artifacts_updated": []}

    # ---- Phase 2: Collect Java_* exports by parsing .so files directly ----
    # native_export facts written by apk_surface/_analyze_targets only carry
    # C++ mangled names; Java_* JNI exports are present in parsed.exports but
    # not always written as native_export facts. Parse .so files directly.
    exports: list[tuple[str, str, int, str]] = []  # library, symbol, offset, digest
    for row in eligible_rows:
        package_id = row.get("package_id", "")
        version_code = str(row.get("version_code", ""))
        digest = row.get("sha256", "").lower()
        decoded = results_root / package_id / version_code / digest / "apktool"
        if not decoded.is_dir():
            continue
        for so_file in decoded.rglob("*.so"):
            try:
                parsed = parse_elf(so_file)
            except (OSError, ValueError):
                continue
            if not parsed or not parsed.ok or not parsed.exports:
                continue
            lib_rel = f"apktool/{so_file.relative_to(decoded).as_posix()}"
            for symbol in parsed.exports:
                sym_name = symbol.name or ""
                if not sym_name.startswith("Java_"):
                    continue
                exports.append((lib_rel, sym_name, symbol.file_offset, digest))

    if not exports:
        return {"matched": 0, "unmatched": 0, "smali_files": smali_files, "artifacts_updated": []}

    # ---- Phase 3: Match exports to smali declarations ----
    matched_by_digest: dict[str, list[tuple[str, str, int, dict]]] = {}
    unmatched = 0

    for library, symbol, offset, digest in exports:
        name = demangle_jni_symbol(symbol)
        if name is None or name.problem or not name.java_class or not name.java_method:
            unmatched += 1
            continue
        sym = SimpleNamespace(name=symbol, file_offset=offset)
        entry, _reason = _map_jni_symbol(library, sym, name, combined_index)
        if entry is not None:
            matched_by_digest.setdefault(digest, []).append((library, symbol, offset, entry))
        else:
            unmatched += 1

    if not matched_by_digest:
        return {"matched": 0, "unmatched": unmatched, "smali_files": smali_files, "artifacts_updated": []}

    # ---- Phase 4: Write native_jni_entry facts to each APK's surface ----
    artifacts_updated = []
    total_matched = 0

    for digest, exports_list in matched_by_digest.items():
        row = next((r for r in eligible_rows if r.get("sha256", "").lower() == digest), None)
        if row is None:
            continue
        package_id = row.get("package_id", "")
        version_code = str(row.get("version_code", ""))
        target = results_root / package_id / version_code / digest / "surface" / "static-analysis.json"
        if not target.is_file():
            continue

        try:
            result = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(result, dict):
            continue

        inventory = result.setdefault("inventory", {})
        if not isinstance(inventory, dict):
            raise TypeError(f"Invalid surface inventory in {target}.")
        jni_entries = inventory.setdefault("jni_entries", [])
        jni_unmapped = inventory.setdefault("jni_unmapped", [])
        native_analysis = inventory.setdefault("native_analysis", [])
        facts = result.setdefault("facts", [])
        findings = result.setdefault("findings", [])
        if not all(
            isinstance(value, list)
            for value in (jni_entries, jni_unmapped, native_analysis, facts, findings)
        ):
            raise TypeError(f"Invalid JNI evidence lists in {target}.")

        def export_key(library_path: str, symbol_name: str) -> tuple[str, str]:
            return library_path.removeprefix("apktool/"), symbol_name

        matched_keys = {
            export_key(library, symbol) for library, symbol, _offset, _entry in exports_list
        }
        mapped_fact_keys = {
            export_key(
                extra.get("library", ""),
                extra.get("symbol", ""),
            )
            for fact in facts
            if isinstance(fact, dict)
            and fact.get("kind") == "native_jni_entry"
            and isinstance((extra := fact.get("extra")), dict)
        }
        inventory_entry_keys = {
            export_key(item.get("library", ""), item.get("symbol", ""))
            for item in jni_entries
            if isinstance(item, dict) and item.get("symbol")
        }

        for library, symbol, offset, entry in exports_list:
            key = export_key(library, symbol)
            if key not in mapped_fact_keys:
                facts.append(
                    {
                        "kind": "native_jni_entry",
                        "value": f"{library}::{symbol}",
                        "evidence": [
                            {"path": library, "offset": offset},
                            {"path": entry["smali_path"], "line": entry["smali_line"]},
                        ],
                        "extra": {
                            "library": library,
                            "symbol": symbol,
                            "java_class": entry["java_class"],
                            "java_method": entry["java_method"],
                            "java_signature": entry["java_signature"],
                            "mapping_confidence": entry["confidence"],
                            "cross_apk_match": True,
                        },
                    },
                )
                mapped_fact_keys.add(key)

            already_in_inventory = key in inventory_entry_keys or any(
                isinstance(item, dict)
                and export_key(item.get("library", ""), "")[0] == key[0]
                and item.get("java_class") == entry["java_class"]
                and item.get("java_method") == entry["java_method"]
                and item.get("java_signature") == entry["java_signature"]
                for item in jni_entries
            )
            if not already_in_inventory:
                jni_entries.append(
                    {
                        "library": key[0],
                        "symbol": symbol,
                        "java_class": entry["java_class"],
                        "java_method": entry["java_method"],
                        "java_signature": entry["java_signature"],
                        "smali_path": entry["smali_path"],
                        "smali_line": entry["smali_line"],
                        "confidence": entry["confidence"],
                    }
                )
                inventory_entry_keys.add(key)

        inventory["jni_unmapped"] = [
            item
            for item in jni_unmapped
            if not (
                isinstance(item, dict)
                and export_key(item.get("library", ""), item.get("symbol", "")) in matched_keys
            )
        ]
        result["facts"] = [
            fact
            for fact in facts
            if not (
                isinstance(fact, dict)
                and fact.get("kind") == "native_jni_unmapped"
                and isinstance((extra := fact.get("extra")), dict)
                and export_key(extra.get("library", ""), extra.get("symbol", "")) in matched_keys
            )
        ]
        result["findings"] = [
            finding
            for finding in findings
            if not (
                isinstance(finding, dict)
                and finding.get("rule_id") == "native_jni_entry_unmapped"
                and isinstance((evidence := finding.get("evidence")), dict)
                and export_key(
                    evidence.get("path", ""),
                    evidence.get("snippet", ""),
                )
                in matched_keys
            )
        ]
        resolved_finding_count = len(findings) - len(result["findings"])

        # Update metrics
        metrics = result.setdefault("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}
            result["metrics"] = metrics
        metrics["native_jni_exports_mapped"] = len(jni_entries)
        metrics["native_jni_exports_unmapped"] = len(inventory["jni_unmapped"])
        metrics["native_jni_mapping_complete"] = (
            metrics.get("native_jni_exports_total", 0)
            == metrics["native_jni_exports_mapped"] + metrics["native_jni_exports_unmapped"]
        )
        metrics["native_findings_emitted"] = max(
            metrics.get("native_findings_emitted", 0) - resolved_finding_count,
            0,
        )
        metrics["finding_count"] = len(result["findings"])
        distinct_findings = {
            (
                finding.get("rule_id"),
                (finding.get("evidence") or {}).get("path"),
                (finding.get("evidence") or {}).get("line"),
            )
            for finding in result["findings"]
            if isinstance(finding, dict)
        }
        metrics["distinct_finding_count"] = len(distinct_findings)
        metrics["fact_count"] = len(result["facts"])

        # Update coverage
        coverage = result.setdefault("coverage", {})
        if not isinstance(coverage, dict):
            coverage = {}
            result["coverage"] = coverage
        coverage["native_jni_mapping"] = (
            "mapped"
            if metrics["native_jni_mapping_complete"]
            and metrics["native_jni_exports_unmapped"] == 0
            else "partial"
        )
        coverage["link_type_method_native"] = "success"

        for library_report in native_analysis:
            if not isinstance(library_report, dict):
                continue
            library_name = library_report.get("path", "")
            library_report["jni_entries"] = sum(
                1
                for item in jni_entries
                if isinstance(item, dict)
                and export_key(item.get("library", ""), "")[0] == library_name
            )
            library_report["jni_unmapped"] = sum(
                1
                for item in inventory["jni_unmapped"]
                if isinstance(item, dict) and item.get("library") == library_name
            )

        try:
            _atomic_write_json(target, result)
            total_matched += len(exports_list)
            artifacts_updated.append({
                "package_id": package_id,
                "version_code": version_code,
                "sha256": digest,
                "matched": len(exports_list),
            })
            if progress is not None:
                progress(f"  Cross-APK JNI: matched {len(exports_list)} export(s) for {digest[:12]}")
        except OSError as exc:
            if progress is not None:
                progress(f"  Cross-APK JNI write FAILED for {digest[:12]}: {exc}")

    return {
        "matched": total_matched,
        "unmatched": unmatched,
        "smali_files": smali_files,
        "artifacts_updated": artifacts_updated,
    }


def refresh_secret_links(
    database,
    workspace: str | Path,
    *,
    run_id: str | None = None,
) -> dict[str, int]:
    """Rebuild surface links from the current TruffleHog scan state."""
    root = Path(workspace).expanduser().resolve()
    results_root = root / "results"
    if results_root.is_symlink():
        raise ValueError("Results directory must not be a symlink.")
    resolved_results = results_root.resolve(strict=True)
    resolved_results.relative_to(root)

    history = database.read_download_history()
    if run_id is not None:
        history_by_hash = {
            row.get("sha256", "").lower(): row for row in history
            if row.get("sha256")
        }
        selected_rows = []
        for selected in database.read_manifest(run_id):
            acquired = history_by_hash.get(selected.get("sha256", "").lower())
            if (
                acquired is not None
                and acquired.get("source") == selected.get("source")
                and acquired.get("run_id") == run_id
                and acquired.get("package_id") == selected.get("package_id")
                and str(acquired.get("version_code", ""))
                == str(selected.get("version_code", ""))
            ):
                selected_rows.append(acquired)
    else:
        selected_rows = history

    processing = database.read_processing_status()
    summary = {"updated": 0, "missing_surface": 0, "failed": 0, "frozen": 0}
    for row in selected_rows:
        package_id = str(row.get("package_id") or "")
        version_code = str(row.get("version_code") or "")
        digest = str(row.get("sha256") or "").lower()
        if (
            not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id)
            or not version_code.isdigit()
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("Malformed artifact identity while refreshing secret links.")

        bundle_dir = results_root / package_id / version_code / digest
        surface_dir = bundle_dir / "surface"
        trufflehog_dir = bundle_dir / "trufflehog"
        static_path = surface_dir / "static-analysis.json"
        findings_path = trufflehog_dir / "findings.json"
        apktool_root = bundle_dir / "apktool"
        for path in (
            bundle_dir, apktool_root, surface_dir, trufflehog_dir,
            static_path, findings_path,
        ):
            if path.is_symlink():
                raise ValueError(f"Refusing symlinked secret-link path: {path}")
        if (bundle_dir / "hashes.sha256").is_file():
            summary["frozen"] += 1
            continue
        if not static_path.is_file():
            summary["missing_surface"] += 1
            continue
        static_path.resolve(strict=True).relative_to(resolved_results)

        result_value = json.loads(static_path.read_text(encoding="utf-8"))
        if not isinstance(result_value, dict):
            raise TypeError(f"Surface result must be a JSON object: {static_path}")
        result = result_value
        scan = processing.get(digest, {})
        scan_status = scan.get("scan_status", "")
        findings: list[dict[str, Any]] | None = None
        linkage_status = "not_run"
        linkage_reason = "TruffleHog has no successful scan status for this artifact."
        if scan_status == "success":
            try:
                findings_value = json.loads(findings_path.read_text(encoding="utf-8"))
                if not isinstance(findings_value, list) or any(
                    not isinstance(item, dict) for item in findings_value
                ):
                    raise ValueError(
                        "findings.json must contain a list of finding objects"
                    )
            except (OSError, ValueError) as exc:
                linkage_status = "failed"
                linkage_reason = f"Cannot use successful TruffleHog output: {exc}"
            else:
                findings = findings_value
                linkage_status = "success"
                linkage_reason = ""
        elif scan_status == "failed":
            linkage_status = "failed"
            linkage_reason = scan.get("error") or "TruffleHog recorded a failed scan."
        elif scan_status == "running":
            linkage_status = "running"
            linkage_reason = "TruffleHog scan is still running."

        diagnostics = result.get("diagnostics")
        if not isinstance(diagnostics, list):
            diagnostics = []
        result["diagnostics"] = [
            item for item in diagnostics
            if not (
                isinstance(item, dict)
                and str(item.get("code", "")).startswith(
                    ("link_", "trufflehog_secret_linkage_")
                )
            )
        ]
        link_coverage: dict[str, str] = {}
        link_diagnostics: list[dict[str, str]] = []
        secret_usage: list[dict[str, Any]] = []
        citation_root = f"{(bundle_dir / 'apktool').relative_to(bundle_dir).as_posix()}/"
        edges = build_link_graph(
            result,
            result.get("dex_analysis"),
            trufflehog_findings=findings,
            tree_root=citation_root,
            finding_root=apktool_root,
            coverage=link_coverage,
            diagnostics=link_diagnostics,
            secret_usage=secret_usage,
        )
        entry_points = build_entry_points(
            result, result.get("dex_analysis"), tree_root=citation_root
        )
        write_links(surface_dir, edges, entry_points)
        write_trace_chains_to_dir(surface_dir, edges, entry_points)
        coverage = result.setdefault("coverage", {})
        if not isinstance(coverage, dict):
            raise TypeError(f"Surface coverage must be a JSON object: {static_path}")
        for key in tuple(coverage):
            if isinstance(key, str) and key.startswith("link_type_"):
                del coverage[key]
        coverage.update(link_coverage)
        coverage["trufflehog_secret_linkage"] = linkage_status
        result["secret_linkage"] = {
            "status": linkage_status,
            "finding_count": len(findings) if findings is not None else None,
        }
        secret_usage_status = linkage_status
        if linkage_status == "success" and any(
            item["usage_status"] == "usage_unverified" for item in secret_usage
        ):
            secret_usage_status = "partial"
        result["secret_usage"] = {
            "status": secret_usage_status,
            "finding_count": len(findings) if findings is not None else None,
            "mapped_count": (
                sum(item["usage_status"] == "mapped" for item in secret_usage)
                if findings is not None else None
            ),
            "usage_unverified_count": (
                sum(
                    item["usage_status"] == "usage_unverified"
                    for item in secret_usage
                )
                if findings is not None else None
            ),
            "findings": secret_usage if findings is not None else None,
        }
        result["diagnostics"].extend(link_diagnostics)
        if linkage_reason:
            result["diagnostics"].append({
                "code": f"trufflehog_secret_linkage_{linkage_status}",
                "message": linkage_reason,
            })
        metrics = result.setdefault("metrics", {})
        metrics["link_edge_count"] = len(edges)
        metrics["entry_point_count"] = len(entry_points)
        finalize_result(result, tree_root=citation_root)
        _atomic_write_json(static_path, result)
        write_handoff(static_path.parent, result, tree_root=citation_root)
        deliver_prompts(bundle_dir)
        summary["updated"] += 1
        if linkage_status == "failed":
            summary["failed"] += 1
    return summary


def _populate_bundle_manifest(
    output_root: Path,
    source_apk: Path,
    row: dict[str, Any],
    *,
    run_id: str | None,
) -> None:
    """Populate ``<bundle>/manifest/`` with acquisition provenance + bundle manifest."""
    manifest_dir = output_root / "manifest"
    if manifest_dir.is_symlink():
        raise ValueError("Refusing symlinked bundle manifest directory.")
    manifest_dir.mkdir(parents=True, exist_ok=True)

    src_bundle = source_apk.parent / "google-play-bundle.json"
    if src_bundle.is_symlink():
        raise ValueError("Refusing symlinked source google-play-bundle.json.")
    copied = False
    if src_bundle.is_file():
        dest_bundle = manifest_dir / "google-play-bundle.json"
        if dest_bundle.is_symlink():
            raise ValueError("Refusing symlinked bundle manifest file.")
        _atomic_write_checkpoint_bytes(dest_bundle, src_bundle.read_bytes())
        copied = True

    provenance_path = manifest_dir / "provenance.json"
    if provenance_path.is_symlink():
        raise ValueError("Refusing symlinked bundle provenance file.")
    _atomic_write_json(
        provenance_path,
        {
            "schema_version": 1,
            "package_id": row.get("package_id", ""),
            "version_code": str(row.get("version_code", "")),
            "sha256": str(row.get("sha256", "")).lower(),
            "run_id": run_id or row.get("run_id"),
            "source": row.get("source", ""),
            "source_apk": str(source_apk),
            "bundle_manifest_present": copied,
        },
    )


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
    # D13: refresh the marker IMMEDIATELY when eligible is computed, not after
    # the first artifact completes. Without this a live run looks dead (eligible=0)
    # until the first artifact finishes, which can take minutes on a large bundle.
    marker_refresh(
        "running",
        summary["eligible"], summary["completed"], summary["failed"],
        summary["skipped"], summary["partial"], summary["finding_count"],
        summary["artifacts"],
    )
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
        # Under D-1 per-bundle workspace: decoded lives under apktool/<component>/.
        # citation_root is derived from the relative path so it adapts
        # automatically: "apktool/" for single-APK, "apktool/<component>/" when
        # component subtrees are present.
        decoded = output_root / "apktool"
        citation_root = f"{decoded.relative_to(output_root).as_posix()}/"
        # D-3: static-analysis.json moves under surface/ so it never collides
        # with decoded output and is always co-located with facts.jsonl and
        # location_map.json.
        target = output_root / "surface" / "static-analysis.json"
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
                and prior_analyzer.get("version") == ANALYZER_VERSION
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
            surface_dir = target.parent
            checkpoint_dir = surface_dir / ".checkpoint"
            stream_path = surface_dir / "facts_stream.jsonl"
            if any(path.is_symlink() for path in (surface_dir, checkpoint_dir, stream_path)):
                raise ValueError("Refusing symlinked surface output or checkpoint path.")
            _populate_bundle_manifest(output_root, source_apk, row, run_id=run_id)
            if force:
                Checkpoint(checkpoint_dir).clear()
                (checkpoint_dir / "sweep_state.json").unlink(missing_ok=True)
                stream_path.unlink(missing_ok=True)
            result = analyze_apk_surface(
                decoded,
                progress=progress,
                tree_root=citation_root,
                output_dir=surface_dir,
                apk_path=source_apk,
                checkpoint_dir=checkpoint_dir,
                finalize=False,
            )
            embedded_dex_result = result.get("dex_analysis")
            _emit_progress(
                progress,
                f"  [Androguard] Parsing DEX, method references and API usage for {package_id}",
            )
            dex_result = analyze_apk_dex(
                source_apk,
                timeout_seconds=dex_timeout_seconds,
                progress=progress,
            )
            dex_result = _merge_dex_analysis(dex_result, embedded_dex_result)
            if dex_result is None:
                raise RuntimeError("DEX analysis unexpectedly produced no result.")
            result["dex_analysis"] = dex_result
            dex_status = str(dex_result.get("status") or "failed")
            result["coverage"]["dex_semantic_analysis"] = dex_status
            if dex_status not in {"success", "not_applicable"}:
                result["status"] = "partial"
            if dex_status != "success":
                result.setdefault("diagnostics", []).extend(dex_result.get("diagnostics", []))
                result.setdefault("limitations", []).extend(dex_result.get("limitations", []))
            # S5: dex-grounded deduction — requested-but-unused sensitive
            # permissions (only when the DEX permission mapping succeeded:
            # no data, no deduction).
            requested = result.get("manifest", {}).get("permissions", []) or []
            if dex_result.get("permission_api_usage"):
                used = {
                    permission
                    for entry in dex_result["permission_api_usage"]
                    for permission in entry.get("permissions", [])
                }
                mismatch = permission_mismatch(requested, used)
                if mismatch is not None:
                    result.setdefault("deductions", []).append(mismatch)
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
            # P4 link graph: typed edges (two citations each) + entry points,
            # written next to facts.jsonl so an AI can walk
            # component -> class -> method -> endpoint -> permission without
            # re-deriving a single join. A failed write is recorded, never
            # hidden: the artifact goes partial and the reason is a diagnostic.
            try:
                link_coverage: dict[str, str] = {}
                link_diagnostics: list[dict[str, str]] = []

                link_edges = build_link_graph(
                    result, dex_result,
                    tree_root=citation_root,
                    coverage=link_coverage,
                    diagnostics=link_diagnostics,
                )
                link_entry_points = build_entry_points(
                    result, dex_result, tree_root=citation_root
                )
                write_links(surface_dir, link_edges, link_entry_points)
                # Write trace chains: entry point → ... → secret paths
                # for the AI to trace end-to-end.
                try:
                    write_trace_chains_to_dir(surface_dir, link_edges, link_entry_points)
                except OSError as exc:
                    result.setdefault("diagnostics", []).append({
                        "code": "trace_chain_write_failed",
                        "message": f"{type(exc).__name__}: {exc}",
                    })
            except OSError as exc:
                result["status"] = "partial"
                result.setdefault("diagnostics", []).append({
                    "code": "link_write_failed",
                    "message": f"{type(exc).__name__}: {exc}",
                })
                _emit_progress(
                    progress,
                    f"  Link graph write FAILED ({type(exc).__name__}: {exc}); "
                    f"artifact marked partial",
                )
            else:
                result["coverage"].update(link_coverage)
                result.setdefault("diagnostics", []).extend(link_diagnostics)
                metrics = result.setdefault("metrics", {})
                metrics["link_edge_count"] = len(link_edges)
                metrics["entry_point_count"] = len(link_entry_points)
                _emit_progress(
                    progress,
                    f"  Links: {len(link_edges)} typed edges + "
                    f"{len(link_entry_points)} entry points",
                )
            finalize_result(result, tree_root=citation_root)
            # The prompt chain is part of the deliverable: copy it into the
            # bundle before the artifact is written so the status is recorded.
            try:
                result["handoff_prompts"] = deliver_prompts(output_root)
            except OSError as exc:
                result["handoff_prompts"] = {
                    "status": "missing",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
                result.setdefault("diagnostics", []).append({
                    "code": "handoff_prompts_failed",
                    "message": f"{type(exc).__name__}: {exc}",
                })
            _atomic_write_json(target, result)
            # S8 handoff contract: the prompt chain reads surface/facts.jsonl
            # and surface/location_map.json. Emit both next to
            # static-analysis.json so no active run points at missing files.
            # A write failure is recorded, never hidden: the artifact becomes
            # partial and the reason lands in diagnostics.
            try:
                handoff_paths = write_handoff(
                    target.parent, result, tree_root=citation_root
                )
            except OSError as exc:
                result["status"] = "partial"
                result.setdefault("diagnostics", []).append({
                    "code": "handoff_write_failed",
                    "message": f"{type(exc).__name__}: {exc}",
                })
                _atomic_write_json(target, result)
                _emit_progress(
                    progress,
                    f"  Handoff write FAILED ({type(exc).__name__}: {exc}); "
                    f"artifact marked partial",
                )
            else:
                _emit_progress(
                    progress,
                    f"  Handoff: {handoff_paths['facts'].name} "
                    f"({len(result.get('facts') or [])} facts) + "
                    f"{handoff_paths['location_map'].name}",
                )
            # Surface artifact is now complete; remove transient resume scratch
            # so freeze hashes only final evidence.
            Checkpoint(checkpoint_dir).clear()
            (checkpoint_dir / "sweep_state.json").unlink(missing_ok=True)
            if checkpoint_dir.is_dir():
                try:
                    checkpoint_dir.rmdir()
                except OSError:
                    pass
            stream_path.unlink(missing_ok=True)
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
                "analyzer": {"id": ANALYZER_ID, "version": ANALYZER_VERSION},
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
    # ---- Cross-APK native JNI matching (crown jewel 5) ----
    # When .so files live in split APKs but smali `native` declarations live
    # in the base APK (or another split), per-APK analysis can't match them.
    # This pass matches all native exports to all smali declarations across
    # the run, writing native_jni_entry facts back to each APK's surface.
    if eligible:
        cross_summary = cross_apk_native_jni_match(results_root, eligible, progress)
        _emit_progress(
            progress,
            f"  Cross-APK JNI matching: {cross_summary['matched']} matched, "
            f"{cross_summary['unmatched']} unmatched, "
            f"{cross_summary['smali_files']} smali files indexed",
        )
        # Update summary artifacts with cross-APK JNI results
        cross_by_digest = {a["sha256"]: a for a in cross_summary["artifacts_updated"]}
        for artifact in summary["artifacts"]:
            if artifact["sha256"] in cross_by_digest:
                artifact_pkg = artifact["package_id"]
                artifact_ver = artifact["version_code"]
                artifact_digest = artifact["sha256"]
                target = results_root / artifact_pkg / artifact_ver / artifact_digest / "surface" / "static-analysis.json"
                try:
                    updated = json.loads(target.read_text(encoding="utf-8"))
                    if isinstance(updated, dict):
                        artifact["coverage"] = updated.get("coverage") or artifact.get("coverage", {})
                        artifact["finding_count"] = len(updated.get("findings") or [])
                except (OSError, ValueError):
                    pass
    if marker_path is not None:
        reused = sum(
            artifact.get("status") == "skipped_reused"
            for artifact in summary["artifacts"]
        )
        unaccounted_skips = max(0, summary["skipped"] - reused)
        marker_status = (
            "failed" if summary["failed"]
            else "partial" if unaccounted_skips or summary["partial"]
            else "success"
        )
        marker_refresh(
            marker_status,
            summary["eligible"], summary["completed"], summary["failed"],
            summary["skipped"], summary["partial"], summary["finding_count"],
            summary["artifacts"],
        )
    return summary
