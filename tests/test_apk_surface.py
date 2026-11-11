from __future__ import annotations


from apkworkbench.analysis.apk_surface import analyze_apk_surface


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
        'const-string v0, "Retry-After"\n',
        encoding="utf-8",
    )
    (root / "smali/com/example/Dependency.smali").write_text(
        ".class public Lokhttp3/OkHttpClient;\n", encoding="utf-8"
    )
    (root / "lib/arm64-v8a/libnative.so").write_bytes(b"native")
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
