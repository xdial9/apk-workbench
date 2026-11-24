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


def _prepare_driver_fixture(tmp_path, *, smali_count: int = 4):
    import hashlib
    import zipfile

    workspace = tmp_path / "ws"
    downloads = workspace / "downloads" / "com.example.resume-1"
    downloads.mkdir(parents=True)
    apk_path = downloads / "base.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
    digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()

    bundle = workspace / "results" / "com.example.resume" / "1" / digest
    decoded = bundle / "apktool"
    (decoded / "smali" / "com" / "example").mkdir(parents=True)
    (decoded / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.resume" android:versionCode="1"><application/></manifest>',
        encoding="utf-8",
    )
    for i in range(smali_count):
        (decoded / "smali" / "com" / "example" / f"S{i}.smali").write_text(
            f'.class public Lcom/example/S{i};\n'
            f'const-string v0, "https://api{i}.example.test/v1/{i}"\n',
            encoding="utf-8",
        )

    row = {
        "run_id": "run-resume",
        "package_id": "com.example.resume",
        "version_code": "1",
        "source": "google_play",
        "local_path": str(apk_path),
        "size": str(apk_path.stat().st_size),
        "sha256": digest,
    }

    class StubDb:
        def read_download_history(self):
            return [row]

        def read_processing_status(self):
            return {digest: {"apktool_status": "success"}}

        def read_manifest(self, run_id):
            return [row]

    return workspace, bundle, StubDb()


def test_run_static_surface_analysis_resumes_from_checkpoint_and_force_resets(tmp_path, monkeypatch):
    import json
    from apkworkbench.analysis import apk_surface
    from apkworkbench.analysis.surface.sweep import SweepState

    workspace, bundle, db = _prepare_driver_fixture(tmp_path, smali_count=4)
    monkeypatch.setattr(apk_surface, "CHECKPOINT_EVERY_FILES", 1)
    monkeypatch.setattr(
        apk_surface,
        "analyze_apk_dex",
        lambda *args, **kwargs: {
            "status": "success",
            "metrics": {},
            "permission_api_usage": [],
        },
    )

    # Simulate a crash mid-sweep after 2 smali files are processed + checkpointed.
    real_sweep_text = SweepState.sweep_text
    calls_run1 = []

    def fail_on_fourth_file(self, **kwargs):
        calls_run1.append(kwargs["relative"])
        if len(calls_run1) == 4:
            raise RuntimeError("simulated SIGKILL mid-sweep")
        return real_sweep_text(self, **kwargs)

    monkeypatch.setattr(SweepState, "sweep_text", fail_on_fourth_file)
    summary1 = apk_surface.run_static_surface_analysis(db, workspace, run_id="run-resume")
    assert summary1["failed"] == 1
    assert (bundle / "surface" / ".checkpoint" / ".surface_checkpoint.json").is_file()
    assert (bundle / "surface" / ".checkpoint" / "sweep_state.json").is_file()
    assert (bundle / "surface" / "facts_stream.jsonl").is_file()

    # Resume: must NOT re-sweep files already in checkpoint, and must keep ALL 4 endpoints.
    monkeypatch.setattr(SweepState, "sweep_text", real_sweep_text)
    swept_run2 = []

    def track_sweep_text(self, **kwargs):
        swept_run2.append(kwargs["relative"])
        return real_sweep_text(self, **kwargs)

    monkeypatch.setattr(SweepState, "sweep_text", track_sweep_text)
    summary2 = apk_surface.run_static_surface_analysis(db, workspace, run_id="run-resume")
    assert summary2["completed"] == 1
    assert len(swept_run2) < len(calls_run1)
    # Transient checkpoint artifacts cleaned up once bundle surface is complete.
    assert not (bundle / "surface" / ".checkpoint").exists()
    assert not (bundle / "surface" / "facts_stream.jsonl").exists()

    stored = json.loads((bundle / "surface" / "static-analysis.json").read_text(encoding="utf-8"))
    endpoints = {ep["value"] for ep in stored["inventory"]["endpoints"]}
    assert {f"https://api{i}.example.test/v1/{i}" for i in range(4)} <= endpoints

    # Forced re-run clears/ignores checkpoint and sweeps all text files cleanly.
    swept_run3 = []

    def track_force_sweep(self, **kwargs):
        swept_run3.append(kwargs["relative"])
        return real_sweep_text(self, **kwargs)

    monkeypatch.setattr(SweepState, "sweep_text", track_force_sweep)
    summary3 = apk_surface.run_static_surface_analysis(
        db, workspace, run_id="run-resume", force=True
    )
    assert summary3["completed"] == 1
    assert len(swept_run3) == 5  # AndroidManifest.xml + 4 smali files
    forced_stored = json.loads((bundle / "surface" / "static-analysis.json").read_text(encoding="utf-8"))
    assert stored == forced_stored


def test_run_marker_writes_computed_eligible_on_first_write(tmp_path, monkeypatch):
    from apkworkbench.analysis import apk_surface

    workspace, _bundle, db = _prepare_driver_fixture(tmp_path, smali_count=1)
    monkeypatch.setattr(
        apk_surface,
        "analyze_apk_dex",
        lambda *args, **kwargs: {"status": "success", "metrics": {}, "permission_api_usage": []},
    )

    marker_writes = []
    real_atomic_write_json = apk_surface._atomic_write_json

    def record_marker(path, payload):
        if path.name == "static-analysis-run.json":
            marker_writes.append(dict(payload))
        return real_atomic_write_json(path, payload)

    monkeypatch.setattr(apk_surface, "_atomic_write_json", record_marker)
    apk_surface.run_static_surface_analysis(db, workspace, run_id="run-resume")

    assert len(marker_writes) >= 2
    assert marker_writes[0]["status"] == "running"
    assert marker_writes[0]["eligible"] == 1
    assert marker_writes[-1]["status"] == "success"
    assert marker_writes[-1]["eligible"] == 1


def test_finalize_result_called_once_per_artifact_in_driver(tmp_path, monkeypatch):
    from apkworkbench.analysis import apk_surface

    workspace, _bundle, db = _prepare_driver_fixture(tmp_path, smali_count=1)
    monkeypatch.setattr(
        apk_surface,
        "analyze_apk_dex",
        lambda *args, **kwargs: {"status": "success", "metrics": {}, "permission_api_usage": []},
    )

    finalize_calls = []
    real_finalize = apk_surface.finalize_result

    def counting_finalize(result, *, tree_root="apktool/"):
        finalize_calls.append(tree_root)
        return real_finalize(result, tree_root=tree_root)

    monkeypatch.setattr(apk_surface, "finalize_result", counting_finalize)
    apk_surface.run_static_surface_analysis(db, workspace, run_id="run-resume")
    assert len(finalize_calls) == 1


def test_native_parse_failure_recorded_as_skipped_in_file_ledger(tmp_path):
    import json
    from apkworkbench.analysis import apk_surface

    root = tmp_path / "apktool"
    (root / "lib" / "arm64-v8a").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest package="com.example.badso"><application/></manifest>', encoding="utf-8"
    )
    (root / "lib" / "arm64-v8a" / "libbroken.so").write_bytes(b"NOT_AN_ELF_FILE")
    (root / "lib" / "arm64-v8a" / "libnotelf.so").write_bytes(b"NOT_AN_ELF_FILE" * 8)
    out = tmp_path / "surface"
    apk_surface.analyze_apk_surface(root, output_dir=out)
    records = {
        json.loads(line)["path"]: json.loads(line)
        for line in (out / "files.jsonl").read_text(encoding="utf-8").splitlines()
    }
    assert records["lib/arm64-v8a/libbroken.so"]["status"] == "undecodable"
    assert records["lib/arm64-v8a/libbroken.so"]["reason"] == "native_elf_parse_failed"
    assert records["lib/arm64-v8a/libnotelf.so"]["status"] == "skipped_binary"
    assert records["lib/arm64-v8a/libnotelf.so"]["reason"] == "native_not_elf"


def test_sweep_checkpoint_cadence_avoids_quadratic_io_and_honors_overrides(tmp_path, monkeypatch):
    from apkworkbench.analysis import apk_surface

    # Default production cadence must stay large enough to avoid quadratic I/O on 30k+ file APKs.
    assert apk_surface.CHECKPOINT_EVERY_FILES >= 1000

    root = tmp_path / "apktool"
    (root / "smali" / "com" / "example").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest package="com.example.cadence"><application/></manifest>', encoding="utf-8"
    )
    for i in range(25):
        (root / "smali" / "com" / "example" / f"C{i}.smali").write_text(
            f'.class public Lcom/example/C{i};\n', encoding="utf-8"
        )

    save_stages: list[tuple[str, int]] = []
    real_save = apk_surface._save_sweep_checkpoint

    def tracking_save(*args, **kwargs):
        save_stages.append((kwargs["stage"], len(kwargs["processed_files"])))
        return real_save(*args, **kwargs)

    monkeypatch.setattr(apk_surface, "_save_sweep_checkpoint", tracking_save)
    monkeypatch.setattr(apk_surface, "CHECKPOINT_EVERY_FILES", 10)
    apk_surface.analyze_apk_surface(root, checkpoint_dir=tmp_path / "ckpt1")
    # 26 text files (manifest + 25 smali) -> mid-sweep saves at 10, 20 + final sweep_done at 26.
    assert save_stages == [("sweep", 10), ("sweep", 20), ("sweep_done", 26)]

    # Elapsed-time cadence also triggers mid-sweep checkpoints even before CHECKPOINT_EVERY_FILES.
    save_stages.clear()
    monkeypatch.setattr(apk_surface, "CHECKPOINT_EVERY_FILES", 10_000)
    monkeypatch.setattr(apk_surface, "CHECKPOINT_EVERY_SECONDS", 0.0)
    apk_surface.analyze_apk_surface(root, checkpoint_dir=tmp_path / "ckpt2")
    assert len(save_stages) == 27
    assert save_stages[-1] == ("sweep_done", 26)


def test_native_so_base64_decoded_string_retargets_without_keyerror(tmp_path):
    """Regression for Alliant crash: .so base64 string has 'line' popped by _retarget_native_evidence."""
    import base64
    from apkworkbench.analysis.surface.handoff import write_handoff

    root = tmp_path / "apktool"
    (root / "lib" / "arm64-v8a").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="org.alliant.mobile"><application/></manifest>',
        encoding="utf-8",
    )
    hidden_url = "https://hidden-native.alliant.example.com/v1/bootstrap"
    encoded = base64.b64encode(hidden_url.encode("ascii")).decode("ascii")
    so_path = root / "lib" / "arm64-v8a" / "liballiant.so"
    write_elf(so_path, symbols=(symbol("Java_org_alliant_Main_init"),))
    # Append printable base64 literal + rate-limit string inside the .so binary
    with so_path.open("ab") as handle:
        handle.write(b"\x00" + encoded.encode("ascii") + b"\x00retry-after\x00")

    result = analyze_apk_surface(root)

    assert result["status"] == "success"
    decoded_facts = [
        fact for fact in result["facts"] if fact["kind"] == "decoded_string"
    ]
    matching = [fact for fact in decoded_facts if hidden_url in fact["value"]]
    assert len(matching) == 1
    ev = matching[0]["evidence"]
    assert len(ev) == 1
    assert ev[0]["path"] == "lib/arm64-v8a/liballiant.so"
    assert ev[0]["line"] is None
    assert isinstance(ev[0].get("offset"), int) and ev[0]["offset"] > 0

    handoff_dir = tmp_path / "surface_out"
    paths = write_handoff(handoff_dir, result)
    assert paths["facts"].is_file()
    assert paths["location_map"].is_file()


def test_decoded_strings_missing_line_and_missing_path_still_record_facts(tmp_path, monkeypatch):
    """Regression: decoded_strings items missing 'line' or 'path' never crash and keep facts."""
    from apkworkbench.analysis import apk_surface
    from apkworkbench.analysis.surface.sweep import SweepState

    root = tmp_path / "apktool"
    (root / "smali" / "com" / "example").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.missing"><application/></manifest>',
        encoding="utf-8",
    )
    (root / "smali" / "com" / "example" / "A.smali").write_text(
        '.class public Lcom/example/A;\n'
        'const-string v0, "https://api.example.com/v1"\n',
        encoding="utf-8",
    )

    real_retarget = apk_surface._retarget_native_evidence

    def inject_partial_items(sweep: SweepState, findings, line_offsets):
        real_retarget(sweep, findings, line_offsets)
        # 1. Missing 'line' (has 'path')
        sweep.decoded_strings.append({
            "decoded": "https://missing-line.example.com/cfg",
            "encoded": "aHR0cHM6Ly9taXNzaW5nLWxpbmUuZXhhbXBsZS5jb20vY2Zn",
            "reveals": ["https://missing-line.example.com/cfg"],
            "path": "AndroidManifest.xml",
        })
        # 2. Missing both 'path' and 'line' (and optional 'encoded'/'reveals')
        sweep.decoded_strings.append({
            "decoded": "https://missing-path.example.com/cfg",
        })
        # 3. Well-formed item (must keep exact shape)
        sweep.decoded_strings.append({
            "decoded": "https://well-formed.example.com/cfg",
            "encoded": "d2VsbC1mb3JtZWQ=",
            "reveals": ["https://well-formed.example.com/cfg"],
            "path": "smali/com/example/A.smali",
            "line": 2,
        })
        # 4. Rate-limit indicator missing 'line' on same path as endpoint
        sweep.rate_limit_indicators.append({
            "path": "smali/com/example/A.smali",
            "snippet": "rate-limit",
        })

    monkeypatch.setattr(apk_surface, "_retarget_native_evidence", inject_partial_items)
    result = apk_surface.analyze_apk_surface(root)

    assert result["status"] == "success"
    by_value = {
        fact["value"]: fact
        for fact in result["facts"]
        if fact["kind"] == "decoded_string"
    }
    assert "https://missing-line.example.com/cfg" in by_value
    assert by_value["https://missing-line.example.com/cfg"]["evidence"] == [
        {"path": "AndroidManifest.xml", "line": None}
    ]

    assert "https://missing-path.example.com/cfg" in by_value
    assert by_value["https://missing-path.example.com/cfg"]["evidence"] == []
    assert by_value["https://missing-path.example.com/cfg"]["encoded"] is None
    assert by_value["https://missing-path.example.com/cfg"]["reveals"] == []

    assert "https://well-formed.example.com/cfg" in by_value
    assert by_value["https://well-formed.example.com/cfg"]["evidence"] == [
        {"path": "smali/com/example/A.smali", "line": 2}
    ]
    assert by_value["https://well-formed.example.com/cfg"]["encoded"] == "d2VsbC1mb3JtZWQ="
    assert by_value["https://well-formed.example.com/cfg"]["reveals"] == [
        "https://well-formed.example.com/cfg"
    ]


def test_workbook_tolerates_single_dict_fact_evidence_and_null_coverage():
    """Audit regression: single-dict fact evidence and None coverage status must not crash."""
    from apkworkbench.analysis.surface.workbook import build_workbook

    wb = build_workbook({
        "facts": [{
            "kind": "decoded_string",
            "value": "https://dict-ev.example.com",
            "fingerprint": "abc123",
            "count": 1,
            "evidence": {"path": "lib/arm64-v8a/libfoo.so", "offset": 64},
        }],
        "findings": [],
        "deductions": [],
        "coverage": {"resource_model": None, "permissions": "success"},
    })
    assert wb["location_ledger"]["facts"][0]["locations"] == ["lib/arm64-v8a/libfoo.so@0x40"]
    lead_ids = {lead["id"] for lead in wb["playbook"]["open_leads"]}
    assert "COV-resource_model" in lead_ids
    assert "FACT-abc123" in lead_ids
