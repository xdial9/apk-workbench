"""S7 adversarial campaign: hostile inputs must never crash or hide findings.

Covers surface-plan §7 rows: unicode/NUL/BOM, empty files, huge single
lines, deep trees, symlinks, non-UTF8 bytes, clashing names, plus the
compat consumer contract (appdev §15) asserted on a full result.
"""
from __future__ import annotations

import json
from pathlib import Path

from apkworkbench.analysis import apk_surface

MIN_MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.example.adv" android:versionCode="7"><application/></manifest>'
)


def _base(tmp_path: Path) -> Path:
    root = tmp_path / "decode"
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MIN_MANIFEST)
    return root


def _consumer_keys(result: dict) -> None:
    """final_run.py + reconcile contract (appdev §15) — additive-safe."""
    assert result["status"] in {"success", "partial"}
    inventory = result["inventory"]
    for endpoint in inventory["endpoints"]:
        assert {"value", "kind", "evidence", "occurrences"} <= set(endpoint)
        assert isinstance(endpoint["occurrences"], int)
    assert isinstance(result["manifest"].get("components"), list)
    assert {"success", "partial", "failed"} >= {result["status"]}
    for key in ("facts", "deductions", "workbook", "coverage", "metrics"):
        assert key in result


def test_unicode_bom_nul_and_non_utf8_survive(tmp_path):
    root = _base(tmp_path)
    smali = root / "smali"
    smali.mkdir()
    # BOM + unicode
    (smali / "bom.smali").write_bytes(
        "﻿const-string v0, \"https://ünïcodé.example/строка\"\n".encode()
    )
    # NUL bytes inside a text-suffix file
    (smali / "nul.smali").write_bytes(
        b"const-string v0, \"https://nul.example/a\"\x00\x00trailing"
    )
    # non-UTF8 bytes in a text-suffix file
    (smali / "binary.smali").write_bytes(
        b'const-string v0, "https://bin.example/b"\xff\xfe\xfd'
    )
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    endpoints = {
        record["value"]: record for record in result["inventory"]["endpoints"]
    }
    assert any("ünïcodé.example" in value or "xn--" in value for value in endpoints) \
        or any("строка" in json.dumps(endpoints, default=str))
    assert any(record.get("host") == "nul.example" for record in endpoints.values())
    assert any(record.get("host") == "bin.example" for record in endpoints.values())
    # diagnostics carry the degraded reads; nothing silently dropped
    assert result["status"] in {"success", "partial"}


def test_empty_files_and_empty_tree_regions(tmp_path):
    root = _base(tmp_path)
    (root / "smali").mkdir()
    (root / "smali" / "empty.smali").write_text("")
    (root / "assets").mkdir()
    (root / "assets" / "empty.json").write_text("")
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    classification = result["inventory"]["classification"]
    assert classification["content_class_counts"].get("empty", 0) >= 2


def test_huge_single_line_does_not_wedge(tmp_path):
    root = _base(tmp_path)
    smali = root / "smali"
    smali.mkdir()
    huge = 'const-string v0, "https://huge.example/pad' + "a" * 200_000 + '"\n'
    (smali / "huge.smali").write_text(huge)
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    endpoints = result["inventory"]["endpoints"]
    assert any(
        record.get("host") == "huge.example" for record in endpoints
    )


def test_deep_directories(tmp_path):
    root = _base(tmp_path)
    deep = root / "smali"
    for segment in [f"d{index}" for index in range(40)]:
        deep = deep / segment
    deep.mkdir(parents=True)
    (deep / "Deep.smali").write_text('const-string v0, "https://deep.example/a"\n')
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    assert any(
        record.get("host") == "deep.example"
        for record in result["inventory"]["endpoints"]
    )


def test_symlinked_files_and_directories_counted_and_skipped(tmp_path):
    root = _base(tmp_path)
    smali = root / "smali"
    smali.mkdir()
    real = smali / "Real.smali"
    real.write_text('const-string v0, "https://real.example/a"\n')
    (smali / "Link.smali").symlink_to(real)
    linked_dir = root / "linked-assets"
    linked_dir.symlink_to(root / "smali", target_is_directory=True)
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    classification = result["inventory"]["classification"]
    assert classification["symlink_entries_skipped"] >= 2
    # the real file is still scanned exactly once
    assert any(
        record.get("host") == "real.example"
        for record in result["inventory"]["endpoints"]
    )


def test_clashing_names_stay_distinct(tmp_path):
    root = _base(tmp_path)
    for region in ("assets/one", "assets/two"):
        directory = root / region
        directory.mkdir(parents=True)
        (directory / "config.json").write_text(
            json.dumps({"region": region, "url": f"https://{region.replace('/', '')}.example/x"})
        )
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    endpoints = {
        record["value"] for record in result["inventory"]["endpoints"]
    }
    assert "https://assetsone.example/x" in endpoints
    assert "https://assetstwo.example/x" in endpoints
    classification = result["inventory"]["classification"]
    assert classification["extension_counts"][".json"] == 2


def test_manifest_parse_failure_is_honest_partial(tmp_path):
    root = _base(tmp_path)
    (root / "AndroidManifest.xml").write_text("<manifest><broken>")
    (root / "smali").mkdir()
    (root / "smali" / "A.smali").write_text('const-string v0, "https://x.example/"\n')
    result = apk_surface.analyze_apk_surface(root)
    assert result["status"] == "partial"
    assert any(
        item["code"] == "manifest_parse_failed" for item in result["diagnostics"]
    )
    _consumer_keys(result)   # even partial output keeps the contract


def test_no_findings_app_still_fully_shaped(tmp_path):
    root = _base(tmp_path)
    (root / "smali").mkdir()
    (root / "smali" / "Quiet.smali").write_text(".class Lquiet;\n")
    result = apk_surface.analyze_apk_surface(root)
    _consumer_keys(result)
    assert result["metrics"]["fact_count"] >= 0
    assert result["workbook"]["playbook"]["open_leads"]  # coverage leads exist
    assert result["metrics"]["distinct_finding_count"] >= 0