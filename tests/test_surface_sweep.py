"""S4 contracts: sweep v2 intelligence (schemes, dedup, classes, decoding)."""
from __future__ import annotations

from pathlib import Path

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import sweep


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


def test_rule_findings_carry_capped_context(tmp_path):
    text = "line-before-2\nline-before-1\n" + 'setJavaScriptEnabled(true)\n' + "line-after-1\nline-after-2\n"
    state = _sweep(tmp_path, text)
    hit = next(f for f in state.findings if f["rule_id"] == "webview_javascript")
    assert hit["evidence"]["line"] == 3
    assert "line-before-1" in hit["evidence"]["context"]
    assert len(hit["evidence"]["context"]) <= sweep.SNIPPET_CONTEXT_CHARS


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