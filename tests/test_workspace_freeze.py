"""Unit 1 freeze + verify-workspace + handoff.json contract tests."""
from __future__ import annotations

import json
import os
from pathlib import Path

from apkworkbench.database.workspace import WorkspaceDatabase

_BUNDLE_ID = "f" * 64


def _make_bundle(root: Path) -> Path:
    bundle = root / "results" / "com.example.app" / "1" / _BUNDLE_ID
    bundle.mkdir(parents=True)
    apktool = bundle / "apktool"
    apktool.mkdir()
    (apktool / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.app" android:versionCode="1"><application/></manifest>',
        encoding="utf-8",
    )
    surface = bundle / "surface"
    surface.mkdir()
    (surface / "static-analysis.json").write_text(
        json.dumps({"status": "success", "findings": []}), encoding="utf-8",
    )
    (surface / "facts.jsonl").write_text("", encoding="utf-8")
    (surface / "location_map.json").write_text(
        json.dumps({"counts": {"facts": 0}}), encoding="utf-8",
    )
    trufflehog = bundle / "trufflehog"
    trufflehog.mkdir()
    (trufflehog / "findings.json").write_text("[]", encoding="utf-8")
    manifest = bundle / "manifest"
    manifest.mkdir()
    (manifest / "google-play-bundle.json").write_text("{}", encoding="utf-8")
    return bundle


def _unfreeze(root: Path) -> None:
    for dirpath, dirs, files in os.walk(root):
        for fname in files:
            os.chmod(Path(dirpath) / fname, 0o644)
        for dirname in dirs:
            os.chmod(Path(dirpath) / dirname, 0o755)


def test_freeze_writes_manifest_and_handoff(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    database = WorkspaceDatabase(tmp_path / "workspace")
    try:
        database.freeze_evidence(bundle)
        hashes_path = bundle / "hashes.sha256"
        handoff_path = bundle / "handoff.json"
        assert hashes_path.is_file()
        assert handoff_path.is_file()

        hashed = {
            line.split("  ", 1)[1]
            for line in hashes_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        assert "apktool/AndroidManifest.xml" in hashed
        assert "surface/static-analysis.json" in hashed
        assert "surface/facts.jsonl" in hashed
        assert "surface/location_map.json" in hashed
        assert "trufflehog/findings.json" in hashed
        assert "manifest/google-play-bundle.json" in hashed
        assert "handoff.json" in hashed

        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        assert handoff["schema_version"] == 1
        assert handoff["bundle_id"] == bundle.name
        assert handoff["analyzer"]["id"] == "apk-surface"
        assert "file_hashes" in handoff
        assert handoff.get("prompts"), "prompt hashes should be recorded"
        assert handoff["file_hashes"]["surface/static-analysis.json"]
    finally:
        _unfreeze(tmp_path / "workspace")


def test_verify_workspace_passes_on_untouched_bundle(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    database = WorkspaceDatabase(tmp_path / "workspace")
    try:
        database.freeze_evidence(bundle)
        result = database.verify_workspace(bundle)
        assert result["status"] == "ok"
        assert result["mismatches"] == []
        assert result["missing"] == []
        assert result["extra"] == []
    finally:
        _unfreeze(tmp_path / "workspace")


def test_verify_workspace_detects_tamper_inside_apktool(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    database = WorkspaceDatabase(tmp_path / "workspace")
    try:
        database.freeze_evidence(bundle)
        target = bundle / "apktool" / "AndroidManifest.xml"
        os.chmod(target, 0o644)  # simulate an attacker restoring write access
        target.write_text("tampered", encoding="utf-8")
        result = database.verify_workspace(bundle)
        assert result["status"] == "failed"
        assert any(m["rel_path"] == "apktool/AndroidManifest.xml" for m in result["mismatches"])
    finally:
        _unfreeze(tmp_path / "workspace")


def test_verify_workspace_detects_extra_file(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    database = WorkspaceDatabase(tmp_path / "workspace")
    try:
        database.freeze_evidence(bundle)
        os.chmod(bundle / "surface", 0o755)
        (bundle / "surface" / "injected.txt").write_text("extra", encoding="utf-8")
        result = database.verify_workspace(bundle)
        assert result["status"] == "failed"
        assert "surface/injected.txt" in result["extra"]
    finally:
        _unfreeze(tmp_path / "workspace")
