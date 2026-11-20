from __future__ import annotations


from apkworkbench.analysis.apk_surface import analyze_apk_surface
from tests.elf_fixtures import symbol, write_elf


def test_apk_surface_analyzer_inventories_manifest_code_endpoints_and_libraries(tmp_path):
    root = tmp_path / "apktool"
    (root / "smali/com/example").mkdir(parents=True)
    (root / "res/xml").mkdir(parents=True)
    (root / "lib/arm64-v8a").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
             package="com.example.app">
          <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
          <uses-permission android:name="android.permission.CAMERA" />
          <application android:debuggable="true" android:usesCleartextTraffic="true"
              android:networkSecurityConfig="@xml/network_security_config">
            <activity android:name=".MainActivity" android:exported="true">
              <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
            </activity>
          </application>
        </manifest>""",
        encoding="utf-8",
    )
    (root / "res/xml/network_security_config.xml").write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="true" />'
        "<debug-overrides /></network-security-config>",
        encoding="utf-8",
    )
    (root / "smali/com/example/Main.smali").write_text(
        '.class public Lcom/example/Main;\n'
        'const-string v0, "http://api.example.test/v1"\n'
        'invoke-virtual {v1, v2}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V\n'
        'invoke-virtual {v1, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;\n'
        'const-string v0, "DES"\n'
        '@GET("/v1/accounts")\n'
        'const-string v0, "X-RateLimit-Limit"\n'
        'const-string v0, "Retry-After"\n'
        'invoke-virtual {v1}, Lokhttp3/Call;->execute()Lokhttp3/Response;\n'
        '.annotation runtime Lretrofit2/http/POST;\n'
        '    value = "/v3/orders"\n'
        '.end annotation\n',
        encoding="utf-8",
    )
    (root / "smali/com/example/Dependency.smali").write_text(
        ".class public Lokhttp3/OkHttpClient;\n", encoding="utf-8"
    )
    # A real ELF (not a 6-byte placeholder): native analysis now parses the
    # file and records which JNI exports map to which Java native methods.
    write_elf(
        root / "lib/arm64-v8a/libnative.so",
        symbols=(symbol("Java_com_example_Main_run"), symbol("malloc", shndx=0)),
    )
    result = analyze_apk_surface(root)

    assert result["status"] == "success"
    assert result["manifest"]["package"] == "com.example.app"
    assert result["manifest"]["target_sdk"] == "35"
    assert result["inventory"]["native_libraries"] == ["lib/arm64-v8a/libnative.so"]
    assert any(item["rule_id"] == "manifest_debuggable" for item in result["findings"])
    assert any(item["rule_id"] == "exported_component" for item in result["findings"])
    assert any(item["rule_id"] == "webview_javascript_interface" for item in result["findings"])
    assert any(item["rule_id"] == "dynamic_code_loading" for item in result["findings"]) is False
    assert any(item["rule_id"] == "process_execution" for item in result["findings"])
    assert any(item["rule_id"] == "weak_cipher" for item in result["findings"])
    assert any(item["category"] == "api_inventory" for item in result["findings"])
    inventory = result["inventory"]
    assert any(item["path"] == "/v1/accounts" and item["http_method"] == "GET" for item in inventory["api_routes"])
    assert any(item["path"] == "/v3/orders" and item["http_method"] == "POST" for item in inventory["api_routes"])
    assert any(
        item["owner"] == "Lokhttp3/Call;" and item["method"] == "execute"
        for item in inventory["api_call_sites"]
    )
    assert "Retrofit" in {item["name"] for item in inventory["api_clients"]}
    assert {"x-ratelimit-limit", "retry-after"} <= {item["name"] for item in inventory["api_headers"]}
    assert inventory["server_rate_limit_assessment"]["status"] == "not_determined_from_static_apk"
    assert len(inventory["rate_limit_indicators"]) == 2
    assert "OkHttp" in {item["name"] for item in result["inventory"]["dependencies"]}
    assert result["coverage"]["runtime_behavior"] == "not_performed"


def test_apk_surface_analyzer_reports_manifest_parse_failure_and_partial_coverage(tmp_path):
    root = tmp_path / "apktool"
    root.mkdir()
    (root / "AndroidManifest.xml").write_text("<manifest", encoding="utf-8")

    result = analyze_apk_surface(root)

    assert result["status"] == "partial"
    assert result["coverage"]["manifest_and_components"] == "failed"
    assert any(item["code"] == "manifest_parse_failed" for item in result["diagnostics"])


def test_apk_surface_analyzer_skips_symlinked_files(tmp_path):
    root = tmp_path / "apktool"
    root.mkdir()
    outside = tmp_path / "outside.smali"
    outside.write_text("http://external.example.test", encoding="utf-8")
    (root / "outside.smali").symlink_to(outside)

    result = analyze_apk_surface(root)

    assert result["inventory"]["file_count"] == 0
    assert result["diagnostics"][0]["code"] == "symlink_entries_skipped"


def test_resource_inventory_reports_counted_not_parsed(tmp_path):
    # The scanner counts res/assets entries but does not decode resources.arsc
    # or layouts. Claiming "success" told the AI a coverage gap was closed.
    root = tmp_path / "apktool"
    (root / "res/values").mkdir(parents=True)
    (root / "assets").mkdir()
    (root / "res/values/strings.xml").write_text("<resources/>", encoding="utf-8")
    (root / "assets/blob.dat").write_bytes(b"\x00\x01\x02")

    result = analyze_apk_surface(root)

    assert result["coverage"]["resource_inventory"] == "counted_not_parsed"
    assert result["inventory"]["resource_and_asset_file_count"] == 2


def test_resource_inventory_is_not_found_without_resource_dirs(tmp_path):
    root = tmp_path / "apktool"
    (root / "smali").mkdir(parents=True)
    (root / "smali/A.smali").write_text(".class LA;", encoding="utf-8")

    result = analyze_apk_surface(root)

    assert result["coverage"]["resource_inventory"] == "not_found"


def test_atomic_write_json_degrades_on_unserializable_object(tmp_path):
    """A leaked third-party object must not abort a run (crash 2026-11-18)."""
    import json

    from apkworkbench.analysis.apk_surface import (
        NON_SERIALIZABLE_MARKER,
        _atomic_write_json,
    )

    class MethodAnalysis:  # shape of the leaked Androguard object
        def __repr__(self) -> str:
            return "<MethodAnalysis leak>"

    target = tmp_path / "surface" / "static-analysis.json"
    payload = {
        "status": "success",
        "diagnostics": [],
        "inventory": {"methods": [MethodAnalysis()]},
        "facts": [{"kind": "endpoint", "value": "https://a.b/"}],
    }
    _atomic_write_json(target, payload)

    written = json.loads(target.read_text(encoding="utf-8"))
    # Everything else is intact; the bad value is an explicit marker.
    assert written["facts"] == [{"kind": "endpoint", "value": "https://a.b/"}]
    marker = written["inventory"]["methods"][0]
    assert marker[NON_SERIALIZABLE_MARKER] is True
    assert "MethodAnalysis" in marker["type"]
    # Degradation is recorded, and the artifact is no longer called success.
    assert written["status"] == "partial"
    codes = [item["code"] for item in written["diagnostics"]]
    assert "non_serializable_value" in codes


def test_atomic_write_json_is_unchanged_for_serializable_payload(tmp_path):
    import json

    from apkworkbench.analysis.apk_surface import _atomic_write_json

    target = tmp_path / "static-analysis.json"
    payload = {"status": "success", "diagnostics": [], "facts": [{"a": 1}]}
    _atomic_write_json(target, payload)

    assert json.loads(target.read_text(encoding="utf-8")) == payload
