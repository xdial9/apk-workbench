"""Regression tests: deductions never emit synthetic phantom evidence paths."""
from __future__ import annotations

import pytest

from apkworkbench.analysis.surface import deductions as ded
from apkworkbench.analysis.surface.facts import FactStore
from apkworkbench.analysis.surface.handoff import build_location_map


@pytest.mark.parametrize(
    "findings",
    [
        None,
        [],
        [{"rule_id": ded.DYNAMIC_CODE_LOADING_RULE}],
        [{"rule_id": ded.DYNAMIC_CODE_LOADING_RULE, "evidence": None}],
        [{"rule_id": ded.DYNAMIC_CODE_LOADING_RULE, "evidence": {}}],
    ],
)
def test_packed_indicator_without_evidence_emits_no_phantom_path(findings):
    facts = FactStore()
    deductions = ded.packed_or_obfuscated(
        facts,
        [ded.DYNAMIC_CODE_LOADING_RULE],
        large_asset_blobs=1,
        short_name_ratio=None,
        findings=findings,
    )
    assert len(deductions) == 1
    item = deductions[0]
    assert item["id"] == "D-PACKED-CANDIDATE"
    assert item["cites"] == []

    exported = facts.export()
    assert len(exported) == 1
    fact = exported[0]
    assert fact["kind"] == "packed_indicator"
    assert fact["evidence"] == []
    assert fact["evidence_count"] == 0

    all_paths = [ev.get("path") for ev in fact["evidence"]]
    assert "apktool/dynamic_code_loading" not in all_paths

    loc_map = build_location_map({"facts": exported, "findings": findings or [], "deductions": deductions})
    fact_entry = next(e for e in loc_map["entries"] if e["source"] == "facts.jsonl")
    assert fact_entry["has_location"] is False
    assert fact_entry["locations"] == []


@pytest.mark.parametrize("short_paths", [None, []])
def test_obfuscation_metric_without_paths_emits_no_phantom_path(short_paths):
    facts = FactStore()
    deductions = ded.packed_or_obfuscated(
        facts,
        [],
        large_asset_blobs=0,
        short_name_ratio=0.75,
        short_name_smali_paths=short_paths,
    )
    assert len(deductions) == 1
    item = deductions[0]
    assert item["id"] == "D-OBFUSCATED-NAMES"
    assert item["cites"] == []

    exported = facts.export()
    assert len(exported) == 1
    fact = exported[0]
    assert fact["kind"] == "obfuscation_metric"
    assert fact["evidence"] == []
    assert fact["evidence_count"] == 0

    all_paths = [ev.get("path") for ev in fact["evidence"]]
    assert "apktool/smali" not in all_paths


def test_packed_and_obfuscated_preserve_real_evidence_when_present():
    facts = FactStore()
    deductions = ded.packed_or_obfuscated(
        facts,
        [ded.DYNAMIC_CODE_LOADING_RULE],
        large_asset_blobs=1,
        short_name_ratio=0.80,
        findings=[
            {
                "rule_id": ded.DYNAMIC_CODE_LOADING_RULE,
                "evidence": {"path": "smali/com/example/Loader.smali", "line": 42},
            }
        ],
        large_asset_blob_paths=["assets/payload.bin"],
        short_name_smali_paths=["smali/a/b.smali"],
    )
    by_id = {d["id"]: d for d in deductions}
    assert by_id["D-PACKED-CANDIDATE"]["cites"] == [
        "finding:dynamic_code_loading@smali/com/example/Loader.smali:42",
        "apktool/assets/payload.bin",
    ]
    assert by_id["D-OBFUSCATED-NAMES"]["cites"] == ["apktool/smali/a/b.smali"]

    by_kind = {f["kind"]: f for f in facts.export()}
    assert by_kind["packed_indicator"]["evidence"] == [
        {"path": "smali/com/example/Loader.smali", "line": 42}
    ]
    assert by_kind["obfuscation_metric"]["evidence"] == [
        {"path": "apktool/smali/a/b.smali"}
    ]
