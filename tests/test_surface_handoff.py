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
    # CAP-FREE: was FACT- + 12-char prefix. Now FULL 64-char fingerprint.
    assert facts[1]["entry_id"] == "FACT-" + ("f" * 64)
    assert facts[1]["fingerprint"] == "f" * 64
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


def test_tree_root_parameter_prefixes_component_citations(tmp_path):
    result = {
        "analyzer": {"id": "apk-surface", "version": "0.3.0"},
        "status": "success",
        "facts": [{
            "kind": "route", "value": "/v1/items", "fingerprint": "a" * 64,
            "count": 1,
            "evidence": [{"path": "smali/com/example/A.smali", "line": 9}],
        }],
        "findings": [{
            "rule_id": "weak_cipher",
            "evidence": {"path": "smali/com/example/C.smali", "line": 5},
        }],
        "deductions": [{
            "id": "api_surface",
            "template": "api_surface",
            "cites": ["smali/com/example/A.smali:9"],
            "facts": ["a" * 64],
        }],
    }
    paths = write_handoff(tmp_path, result, tree_root="apktool/base/")
    location_map = json.loads(paths["location_map"].read_text(encoding="utf-8"))
    locations = [entry["locations"][0] for entry in location_map["entries"]]
    assert locations == [
        "apktool/base/smali/com/example/A.smali:9",
        "apktool/base/smali/com/example/C.smali:5",
        "apktool/base/smali/com/example/A.smali:9",
    ]


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


def test_driver_does_not_mark_dex_not_applicable_as_partial(tmp_path, monkeypatch):
    workspace = tmp_path / "ws"
    downloads = workspace / "downloads" / "com.example.app-1"
    downloads.mkdir(parents=True)
    apk_path = downloads / "config.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.example.app"><application/></manifest>',
        )
    digest = hashlib.sha256(apk_path.read_bytes()).hexdigest()

    artifact_root = workspace / "results" / "com.example.app" / "1" / digest
    decoded = artifact_root / "apktool"
    decoded.mkdir(parents=True)
    (decoded / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.app"><application/></manifest>',
        encoding="utf-8",
    )

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
            "status": "not_applicable",
            "coverage": {"code_model": "not_applicable"},
            "diagnostics": [
                {"code": "dex_not_found", "message": "APK contains no DEX payload."}
            ],
            "limitations": ["No DEX code was available."],
            "metrics": {"dex_files": 0},
            "permission_api_usage": [],
        },
    )

    summary = apk_surface.run_static_surface_analysis(
        StubDatabase(), workspace, run_id="run-1"
    )
    static_payload = json.loads(
        (
            artifact_root / "surface" / "static-analysis.json"
        ).read_text(encoding="utf-8")
    )

    assert summary["completed"] == 1
    assert summary["partial"] == 0
    assert static_payload["status"] == "success"
    assert static_payload["coverage"]["dex_semantic_analysis"] == "not_applicable"
    assert any(item["code"] == "dex_not_found" for item in static_payload["diagnostics"])


def test_native_byte_offset_citation_round_trips_and_line_cites_are_unchanged():
    """N4: native evidence is byte-addressed; text evidence keeps path:line."""
    from apkworkbench.analysis.surface.handoff import render_location

    result = {
        "schema_version": 1,
        "analyzer": {"id": "apk-surface", "version": "0.4.0"},
        "status": "success",
        "facts": [
            {
                "kind": "native_export",
                "value": "lib/arm64-v8a/libfoo.so::Java_com_example_Foo_bar",
                "fingerprint": "a" * 64,
                "count": 1,
                "evidence": [
                    {"path": "lib/arm64-v8a/libfoo.so", "offset": 4096},
                ],
            },
            {
                "kind": "url",
                "value": "https://api.example.test",
                "fingerprint": "b" * 64,
                "count": 1,
                "evidence": [{"path": "smali/com/example/A.smali", "line": 12}],
            },
        ],
        "findings": [
            {
                "rule_id": "native_process_exec",
                "category": "native_execution",
                "confidence": 0.8,
                "evidence": {
                    "path": "lib/arm64-v8a/libfoo.so",
                    "offset": 32,
                    "line": None,
                    "snippet": "system",
                },
            }
        ],
        "deductions": [],
    }

    payload = build_location_map(result)
    native_fact, text_fact, finding = payload["entries"][0], payload["entries"][1], payload["entries"][2]

    assert native_fact["locations"] == ["apktool/lib/arm64-v8a/libfoo.so@0x1000"]
    assert native_fact["address_space"] == "byte"
    assert native_fact["has_location"] is True
    assert text_fact["locations"] == ["apktool/smali/com/example/A.smali:12"]
    assert text_fact["address_space"] == "line"
    assert finding["locations"] == ["apktool/lib/arm64-v8a/libfoo.so@0x20"]
    assert finding["address_space"] == "byte"
    # Existing text rendering is untouched (no offset, no line -> bare path).
    assert render_location("smali/com/example/A.smali", 12) == "apktool/smali/com/example/A.smali:12"
    assert render_location("lib/arm64-v8a/libfoo.so", None) == "apktool/lib/arm64-v8a/libfoo.so"


def test_workbook_location_ledger_renders_native_offsets():
    from apkworkbench.analysis.surface.workbook import build_workbook

    result = {
        "status": "success",
        "coverage": {},
        "facts": [
            {
                "kind": "native_string",
                "value": "https://native.example.test",
                "fingerprint": "c" * 64,
                "count": 1,
                "evidence": [{"path": "lib/arm64-v8a/libfoo.so", "offset": 255}],
            }
        ],
        "findings": [
            {
                "rule_id": "native_anti_debug",
                "confidence": 0.7,
                "evidence": {"path": "lib/arm64-v8a/libfoo.so", "offset": 16, "line": None},
            }
        ],
        "deductions": [],
    }

    ledger = build_workbook(result)["location_ledger"]

    # The workbook ledger cites tree_root-relative paths (its documented rule);
    # native entries add the byte address without changing the prefix rule.
    assert ledger["facts"][0]["locations"] == ["lib/arm64-v8a/libfoo.so@0xff"]
    assert ledger["facts"][0]["address_space"] == "byte"
    assert ledger["findings"][0]["location"] == "lib/arm64-v8a/libfoo.so@0x10"


def test_native_facts_reach_facts_jsonl_with_resolvable_locations(tmp_path):
    """N11: every native fact is citable from the handoff plane."""
    from tests.elf_fixtures import symbol, write_elf

    root = tmp_path / "apktool"
    (root / "smali/com/example").mkdir(parents=True)
    (root / "lib/arm64-v8a").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.example.app"><application /></manifest>',
        encoding="utf-8",
    )
    (root / "smali/com/example/Main.smali").write_text(
        ".class public Lcom/example/Main;\n"
        ".method public native run()V\n.end method\n",
        encoding="utf-8",
    )
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Main_run"),),
        soname="libgood.so",
    )

    result = apk_surface.analyze_apk_surface(root)
    payload = write_handoff(tmp_path / "surface", result)

    facts = [json.loads(line) for line in payload["facts"].read_text(encoding="utf-8").splitlines()]
    kinds = {fact["kind"] for fact in facts}
    assert {"native_elf", "native_export", "native_jni_entry"} <= kinds

    location_map = json.loads(payload["location_map"].read_text(encoding="utf-8"))
    native_entries = [
        entry for entry in location_map["entries"]
        if entry.get("kind") in {"native_elf", "native_export", "native_jni_entry"}
    ]
    assert native_entries
    for entry in native_entries:
        assert entry["has_location"] is True
        assert entry["locations"]
        assert entry["address_space"] in {"byte", "line", "mixed"}
    jni_entry = next(entry for entry in native_entries if entry["kind"] == "native_jni_entry")
    # Symbol record cite is byte-addressed; the smali declaration keeps file:line.
    assert any("@0x" in location for location in jni_entry["locations"])
    assert any(location.endswith("Main.smali:2") for location in jni_entry["locations"])

    # A fully mapped JNI surface is success, not a gap: no false open lead.
    leads = result["workbook"]["playbook"]["open_leads"]
    assert not [lead for lead in leads if lead["id"] == "COV-native_jni_mapping"]
