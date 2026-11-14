"""S5 contracts: fingerprint fact store + deduction templates."""
from __future__ import annotations

from pathlib import Path

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import deductions as ded
from apkworkbench.analysis.surface.facts import FactStore, fingerprint, package_root_histogram


def _entry(relative: str, size: int = 100):
    from types import SimpleNamespace

    return SimpleNamespace(
        relative=relative, suffix="." + relative.rsplit(".", 1)[-1],
        path=Path(relative), size_bytes=size, content_kind=None,
        is_text_candidate=True,
    )


def test_fingerprint_is_stable_and_normalized():
    assert fingerprint("HTTPS://API.Example.com/v2 ") == fingerprint("https://api.example.com/v2")


def test_fact_store_merges_and_caps_representative_evidence():
    store = FactStore()
    for index in range(5):
        store.add("endpoint", "https://a.b/x", evidence={"path": f"f{index}", "line": index})
    exported = store.export()
    assert len(exported) == 1
    record = exported[0]
    assert record["count"] == 5
    assert len(record["evidence"]) == 3
    assert record["evidence_truncated"] is True
    assert record["fingerprint"] == fingerprint("https://a.b/x")


def test_package_root_histogram_owners(tmp_path):
    entries = [
        _entry("smali/com/example/app/Main.smali"),
        _entry("smali/com/example/app/net/Api.smali"),
        _entry("smali/com/vendor/sdk/Tracker.smali"),
        _entry("smali/com/vendor/sdk/Push.smali"),
        _entry("smali/com/vendor/sdk/Util.smali"),
        _entry("smali/com/vendor/sdk/Ad.smali"),
        _entry("smali/com/vendor/sdk/Blob.smali"),
        _entry("smali/androidx/core/Widget.smali"),
        _entry("res/values/strings.xml"),          # ignored: not smali
    ]
    histogram = package_root_histogram(entries, "com.example.app")
    assert histogram["com/example/app"]["owner"] == "app"
    assert histogram["com/vendor/sdk"]["owner"] == "third_party_candidate"
    assert histogram["com/vendor/sdk"]["class_count"] == 5
    assert histogram["androidx/core"]["owner"] == "platform"
    assert "res/values/strings.xml" not in histogram


def test_packed_candidate_fires_only_on_conjunction():
    facts = FactStore()
    assert ded.packed_or_obfuscated(facts, [], 0, None) == []
    packed = ded.packed_or_obfuscated(facts, ["dynamic_code_loading"], 2, None)
    assert any(item["id"] == "D-PACKED-CANDIDATE" for item in packed)
    assert packed[0]["confidence"] == "hint"
    assert packed[0]["facts"], "deduction must cite fingerprints"
    assert all(
        ("decod" in step.lower()) or ("mark" in step.lower())
        for step in packed[0]["next_steps"]
    )


def test_obfuscation_metric_threshold(tmp_path):
    facts = FactStore()
    none_below = ded.packed_or_obfuscated(facts, [], 0, 0.2)
    assert none_below == []
    triggered = ded.packed_or_obfuscated(facts, [], 0, 0.8)
    assert any(item["id"] == "D-OBFUSCATED-NAMES" for item in triggered)


def test_permission_mismatch_only_when_mapping_succeeded():
    requested = [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
    ]
    used = {"android.permission.ACCESS_FINE_LOCATION"}
    mismatch = ded.permission_mismatch(requested, used)
    assert mismatch is not None
    assert mismatch["template"] == "permission_mismatch"
    assert "CAMERA" in mismatch["narrative"]
    assert "FINE_LOCATION" not in mismatch["narrative"].replace("requested sensitive permission(s) with no DEX-level API usage evidence: ", "")
    # both are used -> no deduction
    assert ded.permission_mismatch(requested, {
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA",
    }) is None


def test_api_surface_deduction_cites_endpoints():
    facts = FactStore()
    endpoints = [
        {"canonical": "https://api.example.com/v2", "value": "https://api.example.com/v2",
         "kind": "url", "host": "api.example.com", "host_class": None},
        {"canonical": "http://10.0.0.3/x", "value": "http://10.0.0.3/x",
         "kind": "url", "host": "10.0.0.3", "host_class": "private"},
    ]
    deduction = ded.api_surface(facts, endpoints, {"v2/one": {"http_method": "GET"}})
    assert deduction is not None
    assert "api.example.com" in deduction["narrative"]
    assert "10.0.0.3" not in deduction["narrative"]   # private hosts excluded
    assert len(deduction["facts"]) == 2               # one public URL + one route


def test_analyzer_emits_facts_deductions_and_histogram(tmp_path):
    root = tmp_path / "decode"
    smali_dir = root / "smali" / "com" / "vendor" / "sdk"
    smali_dir.mkdir(parents=True)
    for name in ("Abc", "Def", "Ghi", "Jkl", "Mno", "Pqr", "Stu", "Vwx",
                 "Yza", "Bcd", "Cde", "Fgh", "Hij", "Klm", "Nop", "Qrs",
                 "Tuv", "Wxy", "Zab", "Cde2"):
        (smali_dir / f"{name}.smali").write_text(".class Lcom/vendor/sdk;")

    (root / "assets").mkdir()
    (root / "assets" / "bigblob").write_bytes(b"\x00" * 1_500_000)
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.ded" android:versionCode="3">'
        '<application><activity android:name=".M" android:exported="true"/>'
        "</application></manifest>"
    )
    (root / "smali" / "com" / "example" / "ded").mkdir(parents=True)
    (root / "smali" / "com" / "example" / "ded" / "M.smali").write_text(
        "setJavaScriptEnabled(true)\n"
        "DexClassLoader\n"
    )

    result = apk_surface.analyze_apk_surface(root)

    assert isinstance(result["facts"], list) and result["facts"]
    fingerprints = {item["fingerprint"] for item in result["facts"]}
    ids = {item["id"] for item in result["deductions"]}
    assert "D-SDK-HISTOGRAM" in ids
    assert "D-OBFUSCATED-NAMES" in ids       # every smali stem short -> ratio 1.0
    assert "D-PACKED-CANDIDATE" in ids       # DexClassLoader string + 1.5MB blob
    assert "D-API-SURFACE" not in ids        # no URL facts in this fixture
    # every deduction cites fact fingerprints that exist in the store
    for item in result["deductions"]:
        assert item["facts"], item["id"]
        for fp in item["facts"]:
            assert fp in fingerprints, (item["id"], fp)
    histogram = result["sdk_histogram"]
    assert histogram["com/vendor/sdk"]["owner"] == "third_party_candidate"