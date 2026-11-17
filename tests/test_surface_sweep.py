"""S4 contracts: sweep v2 intelligence (schemes, dedup, classes, decoding)."""
from __future__ import annotations

import re
from pathlib import Path

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import sweep
from apkworkbench.analysis.surface.sweep import SweepState


RULES = [(rule, __import__("re").compile(rule[4], __import__("re").IGNORECASE))
         for rule in apk_surface.CODE_RULES]
MARKERS = apk_surface.DEPENDENCY_MARKERS


def _sweep(tmp_path: Path, text: str, name: str = "smali/com/x/A.smali"):
    state = sweep.SweepState(MARKERS)
    state.api_clients = {name: [] for name in apk_surface.API_CLIENT_MARKERS}
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    state.sweep_text(
        relative=name, path=path, text=text,
        code_rules=RULES,
        api_client_markers=apk_surface.API_CLIENT_MARKERS,
        api_invoke_owner_re=apk_surface.API_INVOKE_OWNER_RE,
        smali_invoke_re=apk_surface.SMALI_INVOKE_RE,
        header_re=apk_surface.API_HEADER_RE,
        rate_limit_re=apk_surface.RATE_LIMIT_RE,
        dependency_markers=MARKERS,
        emit=lambda message: None,
    )
    return state


def test_generic_schemes_classified(tmp_path):
    text = (
        'const-string v0, "content://com.provider/items"\n'
        'const-string v1, "intent://pay/host#Intent"\n'
        'const-string v2, "myapp+custom://deep/link"\n'
        'const-string v3, "https://api.example.com/v2"\n'
    )
    state = _sweep(tmp_path, text)
    by_value = {e["value"]: e for e in state.api_endpoints.values()}
    assert by_value["content://com.provider/items"]["scheme"] == "content"
    assert by_value["intent://pay/host#Intent"]["scheme"] == "intent"
    assert by_value["myapp+custom://deep/link"]["scheme"] == "myapp+custom"
    assert by_value["https://api.example.com/v2"]["kind"] == "url"


def test_canonical_dedup_merges_url_variants(tmp_path):
    text = (
        '"https://api.example.com/v2/things"\n'
        '"https://api.example.com/v2/things/"\n'
        '"https://API.example.com/v2/things"\n'
    )
    state = _sweep(tmp_path, text)
    assert len(state.api_endpoints) == 1
    record = next(iter(state.api_endpoints.values()))
    assert record["occurrences"] == 3
    assert record["evidence"][0]["line"] == 1


def test_userinfo_flag_and_finding(tmp_path):
    state = _sweep(tmp_path, '"https://admin:s3cret@backend.example/upload"')
    record = next(iter(state.api_endpoints.values()))
    assert "userinfo" in record["flags"]
    assert any(f["rule_id"] == "url_embedded_credentials" for f in state.findings)


def test_private_and_idn_host_classes(tmp_path):
    text = (
        '"http://10.1.2.3/x"\n'
        '"http://192.168.0.5/x"\n'
        '"http://localhost:8080/dev"\n'
        '"https://xn--bcher-kva.example/feed"\n'
        '"https://public.example.net/ok"\n'
    )
    state = _sweep(tmp_path, text)
    by_host = {e["host"]: e for e in state.api_endpoints.values() if e.get("host")}
    assert by_host["10.1.2.3"]["host_class"] == "private"
    assert by_host["192.168.0.5"]["host_class"] == "private"
    assert by_host["localhost"]["host_class"] == "reserved"
    assert by_host["xn--bcher-kva.example"]["host_class"] == "idn"
    assert by_host["public.example.net"]["host_class"] is None
    # dev-path marker recorded
    assert any(
        "dev_path" in e["flags"] for e in state.api_endpoints.values()
        if (e.get("path") or "").lower().startswith("/dev")
    )


def test_ipv6_and_host_port_pairs(tmp_path):
    text = (
        '"http://[2001:db8::1]:8080/x"\n'
        '"10.0.0.9:9090/health"\n'
        '"gateway.internal:8443"\n'
    )
    state = _sweep(tmp_path, text)
    kinds = {(e["kind"], e["value"]) for e in state.api_endpoints.values()}
    assert ("ipv6_candidate", "2001:db8::1") in kinds
    assert ("host_port", "10.0.0.9:9090") in kinds
    assert ("host_port", "gateway.internal:8443") in kinds


def test_host_port_filter_still_rejects_java_identifiers(tmp_path):
    # The Java-identifier filter must keep working for domain-shaped values;
    # the IPv4 exemption above must not turn it off.
    state = _sweep(tmp_path, '"android.permission.camera:8080"\n')
    kinds = {(e["kind"], e["value"]) for e in state.api_endpoints.values()}
    assert ("host_port", "android.permission.camera:8080") not in kinds


def test_base64_candidate_decoded_to_endpoint(tmp_path):
    import base64

    hidden = base64.b64encode(b"https://secret.example/telemetry").decode()
    assert hidden and len(hidden) % 4 == 0
    state = _sweep(tmp_path, f'const-string v0, "{hidden}"\n')
    assert state.decoded_strings, state.decoded_strings
    assert any(
        "secret.example" in item["decoded"] for item in state.decoded_strings
    )
    assert any(f["rule_id"] == "encoded_string_decoded" for f in state.findings)


def test_base64_plain_words_not_flagged(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "AuthenticationRequired"\n')
    assert state.decoded_strings == []


def test_retrofit_window_bounded(tmp_path):
    # value line far beyond the window must NOT be misattributed
    far = "\n" * 30 + '.annotation value = "bogus"\n'
    text = (
        ".annotation runtime Lretrofit2/http/GET;\n"
        'value = "v2/real"\n'
        ".end annotation\n" + far
    )
    state = _sweep(tmp_path, text)
    assert "v2/real" in state.api_routes
    assert "bogus" not in state.api_routes


def test_headers_carry_context_class(tmp_path):
    state = _sweep(tmp_path, "X-Trace-Id: abc\n", name="docs/notes.md")
    entry = state.api_headers["x-trace-id"][0]
    assert entry["context_class"] == "doc_or_other"


def test_rule_findings_carry_full_context(tmp_path):
    text = "line-before-2\nline-before-1\n" + 'setJavaScriptEnabled(true)\n' + "line-after-1\nline-after-2\n"
    state = _sweep(tmp_path, text)
    hit = next(f for f in state.findings if f["rule_id"] == "webview_javascript")
    assert hit["evidence"]["line"] == 3
    # CAP-FREE: was capped to SNIPPET_CONTEXT_CHARS (500). Now full 5-line context, no char cap.
    assert "line-before-2" in hit["evidence"]["context"]
    assert "line-before-1" in hit["evidence"]["context"]
    assert "line-after-1" in hit["evidence"]["context"]
    assert "line-after-2" in hit["evidence"]["context"]


def test_ipv6_bracket_shape_without_colon_preserved(tmp_path):
    # BRACKET_IPV6_RE's alphabet allows colon-free bracket shapes; the
    # character gate must not silently drop them (behavior parity).
    state = _sweep(tmp_path, 'const-string v0, "[deadbeef]"\n')
    assert any(
        e["kind"] == "ipv6_candidate" and e["value"] == "deadbeef"
        for e in state.api_endpoints.values()
    )


def test_dependency_evidence_is_file_level_not_per_line(tmp_path):
    text = (
        "Lokhttp3/OkHttpClient;\n"
        "Lokhttp3/OkHttpClient;\n"
        "Lretrofit2/Retrofit;\n"
    )
    state = _sweep(tmp_path, text)
    # same fact the old per-line appends were deduped into: one path per file
    assert state.dependency_evidence["OkHttp"] == ["smali/com/x/A.smali"]
    assert state.dependency_evidence["Retrofit"] == ["smali/com/x/A.smali"]


def test_rate_limit_proximity_uses_all_evidence(tmp_path):
    text = (
        '"https://api.example.com/one"\n'
        "checkRateLimit()\n"
        '"https://api.example.com/one"\n'   # second evidence near the signal
    )
    state = _sweep(tmp_path, text)
    record = next(iter(state.api_endpoints.values()))
    assert record["occurrences"] == 2
    record["nearby_rate_limit_indicators"] = [
        signal for signal in state.rate_limit_indicators
        for ev in record["evidence"]
        if signal["path"] == ev["path"] and abs(signal["line"] - ev["line"]) <= 30
    ]
    assert record["nearby_rate_limit_indicators"]

def test_insecure_http_ignores_the_android_namespace():
    # Every manifest declares xmlns:android="http://schemas.android.com/...".
    # Flagging it put a cleartext finding in every artifact ever scanned.
    pattern = r"""http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"""
    rules = (
        (("insecure_http", "network", "medium", "t", pattern, 0.96, "why"),
         re.compile(pattern, re.IGNORECASE)),
    )
    state = SweepState({})
    state.sweep_text(
        relative="AndroidManifest.xml",
        path=Path("AndroidManifest.xml"),
        text='<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
        code_rules=rules,
        api_client_markers={},
        api_invoke_owner_re=re.compile("x^"),
        smali_invoke_re=re.compile("x^"),
        header_re=re.compile("x^"),
        rate_limit_re=re.compile("x^"),
        dependency_markers={},
        emit=lambda message: None,
    )
    assert not [item for item in state.findings if item["rule_id"] == "insecure_http"]


def test_insecure_http_still_flags_a_real_cleartext_endpoint():
    pattern = r"""http://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"""
    rules = (
        (("insecure_http", "network", "medium", "t", pattern, 0.96, "why"),
         re.compile(pattern, re.IGNORECASE)),
    )
    state = SweepState({})
    state.sweep_text(
        relative="smali/A.smali",
        path=Path("A.smali"),
        text='const-string v0, "http://api.example.com/v1"',
        code_rules=rules,
        api_client_markers={},
        api_invoke_owner_re=re.compile("x^"),
        smali_invoke_re=re.compile("x^"),
        header_re=re.compile("x^"),
        rate_limit_re=re.compile("x^"),
        dependency_markers={},
        emit=lambda message: None,
    )
    hits = [item for item in state.findings if item["rule_id"] == "insecure_http"]
    assert len(hits) == 1


# ---- P5 detection-breadth fixtures (positive + negative per rule) ----------

def _rule_fires(state, rule_id: str) -> bool:
    return any(f["rule_id"] == rule_id for f in state.findings)


def test_certificate_pinning_present_positive(tmp_path):
    state = _sweep(
        tmp_path,
        'const-string v0, "sha256/A9bC8dE7fG6hI5jK4lM3nO2pQ1rS0tU9vW8xY7z"\n'
        '.field pin: Lokhttp3/CertificatePinner;\n',
    )
    assert _rule_fires(state, "certificate_pinning_present")


def test_certificate_pinning_present_negative(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "https://api.example.test/v1"\n')
    assert not _rule_fires(state, "certificate_pinning_present")


def test_certificate_pinning_bypass_positive(tmp_path):
    state = _sweep(tmp_path, 'setCertificatePinner(null)\n', name="smali/com/x/B.smali")
    assert _rule_fires(state, "certificate_pinning_bypass")


def test_certificate_pinning_bypass_negative(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "pin-set: {hash}"\n')
    assert not _rule_fires(state, "certificate_pinning_bypass")


def test_keystore_credential_access_positive(tmp_path):
    state = _sweep(tmp_path, 'invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;\n')
    assert _rule_fires(state, "keystore_credential_access")


def test_keystore_credential_access_negative(tmp_path):
    state = _sweep(tmp_path, 'invoke-virtual {v0, "data"}, Ljava/io/File;->write(Ljava/lang/String;)V\n')
    assert not _rule_fires(state, "keystore_credential_access")


def test_sql_string_concatenation_positive(tmp_path):
    state = _sweep(
        tmp_path,
        'const-string v0, "SELECT * FROM t WHERE x = " + v1\n',
    )
    assert _rule_fires(state, "sql_string_concatenation")


def test_sql_string_concatenation_negative(tmp_path):
    state = _sweep(tmp_path, 'invoke-virtual {v0, v1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V\n')
    assert not _rule_fires(state, "sql_string_concatenation")


def test_path_traversal_positive(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "../../etc/passwd"\n')
    assert _rule_fires(state, "path_traversal")


def test_path_traversal_negative(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "assets/config.json"\n')
    assert not _rule_fires(state, "path_traversal")


def test_intent_redirection_positive(tmp_path):
    state = _sweep(
        tmp_path,
        'invoke-virtual {v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n',
    )
    assert _rule_fires(state, "intent_redirection")


def test_intent_redirection_negative(tmp_path):
    state = _sweep(tmp_path, 'invoke-virtual {v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n')
    assert not _rule_fires(state, "intent_redirection")


def test_overlay_window_positive(tmp_path):
    state = _sweep(tmp_path, 'const/4 v0, 0x6f010001\n.line TYPE_APPLICATION_OVERLAY\n')
    assert _rule_fires(state, "overlay_window")


def test_overlay_window_negative(tmp_path):
    state = _sweep(tmp_path, 'const/4 v0, 0x6f010001\n.line WINDOW_TYPE_NORMAL\n')
    assert not _rule_fires(state, "overlay_window")


def test_clipboard_access_positive(tmp_path):
    state = _sweep(tmp_path, 'invoke-virtual {v0}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;\n')
    assert _rule_fires(state, "clipboard_access")


def test_clipboard_access_negative(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "clip"\n')
    assert not _rule_fires(state, "clipboard_access")


def test_accessibility_service_positive(tmp_path):
    state = _sweep(tmp_path, '.class public Lcom/x/MyAccessibilityService;\n.super Landroid/accessibilityservice/AccessibilityService;\n')
    assert _rule_fires(state, "accessibility_service")


def test_accessibility_service_negative(tmp_path):
    state = _sweep(tmp_path, '.class public Lcom/x/Worker;\n.super Ljava/lang/Object;\n')
    assert not _rule_fires(state, "accessibility_service")


def test_root_emulator_detection_positive(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "/system/bin/su"\n')
    assert _rule_fires(state, "root_emulator_detection")


def test_root_emulator_detection_negative(tmp_path):
    state = _sweep(tmp_path, 'const-string v0, "normal/file/path"\n')
    assert not _rule_fires(state, "root_emulator_detection")


def test_exported_provider_risk_positive(tmp_path):
    state = _sweep(
        tmp_path,
        'invoke-virtual {v0}, Landroid/content/ContentResolver;->insert(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/Object;)Landroid/net/Uri;\n',
    )
    assert _rule_fires(state, "exported_provider_risk")


def test_exported_provider_risk_negative(tmp_path):
    state = _sweep(tmp_path, 'invoke-virtual {v0}, Ljava/lang/String;->length()I\n')
    assert not _rule_fires(state, "exported_provider_risk")


def test_task_hijacking_positive(tmp_path):
    state = _sweep(
        tmp_path,
        '<application android:taskAffinity="com.attacker.Foo">\n',
        name="AndroidManifest.xml",
    )
    assert _rule_fires(state, "task_hijacking")


def test_task_hijacking_negative(tmp_path):
    state = _sweep(tmp_path, '<activity android:name=".Main" />\n')
    assert not _rule_fires(state, "task_hijacking")
