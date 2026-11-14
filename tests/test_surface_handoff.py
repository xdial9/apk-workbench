"""S8 handoff contract: facts.jsonl + location_map.json are emitted.

The prompt chain (prompts/0.txt..6.txt) tells the terminal analyst to read
`surface/facts.jsonl` and `surface/location_map.json`. These tests lock the
files into existence, keep them deterministic, and prove the driver writes
them next to static-analysis.json.
"""
from __future__ import annotations

import hashlib
import json
import zipfile

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface.handoff import (
    FACTS_FILENAME,
    LOCATION_MAP_FILENAME,
    build_location_map,
    write_handoff,
)


def _sample_result() -> dict:
    return {
        "schema_version": 1,
        "analyzer": {"id": "apk-surface", "version": "0.3.0"},
        "status": "success",
        "artifact": {
            "package_id": "com.example.app",
            "version_code": 7,
            "sha256": "ab" * 32,
        },
        "facts": [
            {
                "kind": "url",
                "value": "https://user:pw@api.example.test/v1/items",
                "fingerprint": "f" * 64,
                "count": 3,
                "evidence": [
                    {"path": "apktool/smali/com/example/A.smali", "line": 12},
                    {"path": "apktool/smali/com/example/B.smali", "line": 88},
                ],
                "flags": ["userinfo"],
                "host_class": "public",
            },
            {
                "kind": "domain",
                "value": "example.test",
                "fingerprint": "e" * 64,
                "count": 1,
                "evidence": [
                    {"path": "apktool/res/values/strings.xml", "line": 4},
                ],
            },
        ],
        "findings": [
            {
                "rule_id": "weak_cipher",
                "category": "crypto",
                "confidence": "hint",
                "evidence": {
                    "path": "apktool/smali/com/example/C.smali",
                    "line": 5,
                    "context": ["line 4", "line 5", "line 6"],
                },
            },
        ],
        "deductions": [
            {
                "id": "api_surface",
                "template": "api_surface",
                "confidence": "deduced",
                "narrative": "3 API endpoints over 1 host",
                "cites": ["apktool/smali/com/example/A.smali:12"],
                "facts": ["f" * 64],
                "next_steps": ["trace call sites"],
            },
        ],
        "coverage": {"dex_semantic_analysis": "success"},
        "metrics": {},
    }


def test_facts_jsonl_matches_fact_order_and_is_parseable(tmp_path):
    result = _sample_result()
    paths = write_handoff(tmp_path, result)
    lines = paths["facts"].read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(result["facts"])
    parsed = [json.loads(line) for line in lines]
    assert [item["value"] for item in parsed] == [
        fact["value"] for fact in result["facts"]
    ]
    assert all(item["fingerprint"] for item in parsed)


def test_location_map_cites_every_fact_line_finding_and_deduction(tmp_path):
    result = _sample_result()
    paths = write_handoff(tmp_path, result)
    location_map = json.loads(paths["location_map"].read_text(encoding="utf-8"))

    assert location_map["schema_version"] == 1
    assert location_map["counts"] == {
        "facts": 2, "findings": 1, "deductions": 1, "entries": 4,
    }
    assert location_map["artifact"]["package_id"] == "com.example.app"

    facts = {entry["facts_jsonl_line"]: entry
             for entry in location_map["entries"] if entry["source"] == "facts.jsonl"}
    assert set(facts) == {1, 2}
    assert facts[1]["entry_id"] == "FACT-" + ("f" * 12)
    assert facts[1]["locations"] == [
        "apktool/smali/com/example/A.smali:12",
        "apktool/smali/com/example/B.smali:88",
    ]
    assert facts[1]["occurrences"] == 3
    assert facts[1]["has_location"] is True

    finding = next(
        entry for entry in location_map["entries"]
        if entry["source"] == "static-analysis.json findings"
    )
    assert finding["rule_id"] == "weak_cipher"
    assert finding["locations"] == ["apktool/smali/com/example/C.smali:5"]
    assert finding["context"] == ["line 4", "line 5", "line 6"]

    deduction = next(
        entry for entry in location_map["entries"]
        if entry["source"] == "static-analysis.json deductions"
    )
    assert deduction["deduction_id"] == "api_surface"
    assert deduction["locations"] == ["apktool/smali/com/example/A.smali:12"]


def test_location_map_keeps_locationless_entries_visible(tmp_path):
    result = _sample_result()
    result["facts"][0]["evidence"] = []
    paths = write_handoff(tmp_path, result)
    location_map = json.loads(paths["location_map"].read_text(encoding="utf-8"))
    fact = next(e for e in location_map["entries"] if e["source"] == "facts.jsonl")
    # Never silently drop an entry that lacks a citation; mark it honestly.
    assert fact["has_location"] is False
    assert fact["locations"] == []


def test_handoff_output_is_byte_identical_on_rerun(tmp_path):
    result = _sample_result()
    first = write_handoff(tmp_path, result)
    facts_first = first["facts"].read_bytes()
    map_first = first["location_map"].read_bytes()
    second = write_handoff(tmp_path, result)
    assert second["facts"].read_bytes() == facts_first
    assert second["location_map"].read_bytes() == map_first
    # whole-file rewrite, never an append
    assert len(facts_first.decode("utf-8").splitlines()) == 2


def test_location_requires_a_real_line_number():
    payload = build_location_map({
        "facts": [{
            "kind": "url", "value": "https://a.test/", "fingerprint": "a" * 64,
            "count": 0,
            "evidence": [{"path": "apktool/x.smali"}, {"path": ""}],
        }],
        "findings": [],
        "deductions": [],
    })
    entry = payload["entries"][0]
    assert entry["locations"] == ["apktool/x.smali"]
    assert "apktool/x.smali:" not in entry["locations"][0]


def _write_tree(root):
    (root / "smali/com/example").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
             package="com.example.app">
          <application android:debuggable="true">
            <activity android:name=".MainActivity" android:exported="true" />
          </application>
        </manifest>""",
        encoding="utf-8",
    )
    (root / "apktool.yml").write_text("version: 2.9.0\n", encoding="utf-8")
    (root / "smali/com/example/Main.smali").write_text(
        '.class public Lcom/example/Main;\n'
        'const-string v0, "https://api.example.test/v1/items"\n'
        'invoke-virtual {v1}, Lokhttp3/Call;->execute()Lokhttp3/Response;\n',
        encoding="utf-8",
    )


def test_driver_emits_handoff_files_beside_static_analysis(tmp_path, monkeypatch):
    workspace = tmp_path / "ws"
    downloads = workspace / "downloads" / "com.example.app-1"
    downloads.mkdir(parents=True)
    apk_path = downloads / "base.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", "stub")
    digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()

    artifact_root = workspace / "results" / "com.example.app" / "1" / digest
    _write_tree(artifact_root / "apktool")

    row = {
        "run_id": "run-1",
        "package_id": "com.example.app",
        "version_code": "1",
        "source": "google_play",
        "local_path": str(apk_path),
        "size": str(apk_path.stat().st_size),
        "sha256": digest,
    }

    class StubDatabase:
        def read_download_history(self):
            return [row]

        def read_processing_status(self):
            return {digest: {"apktool_status": "success"}}

        def read_manifest(self, run_id):
            return [row]

    monkeypatch.setattr(
        apk_surface,
        "analyze_apk_dex",
        lambda *args, **kwargs: {
            "status": "success",
            "metrics": {},
            "permission_api_usage": [],
        },
    )

    summary = apk_surface.run_static_surface_analysis(
        StubDatabase(), workspace, run_id="run-1"
    )

    assert summary["completed"] == 1
    facts_path = artifact_root / FACTS_FILENAME
    map_path = artifact_root / LOCATION_MAP_FILENAME
    assert facts_path.is_file()
    assert map_path.is_file()

    location_map = json.loads(map_path.read_text(encoding="utf-8"))
    assert location_map["counts"]["facts"] == len(
        facts_path.read_text(encoding="utf-8").splitlines()
    )
    assert location_map["artifact"]["sha256"] == digest
    assert any(
        entry["locations"] and entry["locations"][0].startswith("apktool/")
        for entry in location_map["entries"]
    )
