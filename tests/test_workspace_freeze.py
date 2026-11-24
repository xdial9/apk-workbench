"""Unit 1 freeze + verify-workspace + handoff.json contract tests."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase

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
        status_path = database.write_stage_status(
            bundle / "stages" / "surface",
            stage="surface",
            status="partial",
            counts={"artifacts": 1, "findings": 2},
            coverage={"files": "partial"},
            diagnostics=[{"code": "fixture_partial", "message": "Synthetic partial result."}],
        )
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
        assert "stages/surface/status.json" in hashed
        assert "handoff.json" in hashed

        status = json.loads(status_path.read_text(encoding="utf-8"))
        assert status == {
            "schema_version": 1,
            "stage": "surface",
            "status": "partial",
            "counts": {"artifacts": 1, "findings": 2},
            "coverage": {"files": "partial"},
            "diagnostics": [
                {"code": "fixture_partial", "message": "Synthetic partial result."}
            ],
        }
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        assert handoff["schema_version"] == 1
        assert handoff["bundle_id"] == bundle.name
        assert handoff["analyzer"]["id"] == "apk-surface"
        assert "file_hashes" in handoff
        assert handoff.get("prompts"), "prompt hashes should be recorded"
        assert handoff["file_hashes"]["surface/static-analysis.json"]
        assert not os.stat(bundle / "stages").st_mode & 0o222
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
        assert result["writable"] == []
        assert not os.stat(bundle / "hashes.sha256").st_mode & 0o222
    finally:
        _unfreeze(tmp_path / "workspace")


def test_freeze_and_verify_include_dotfiles(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    dotfile = bundle / "surface" / ".analysis-metadata"
    dotfile.write_text("hidden evidence metadata", encoding="utf-8")
    database = WorkspaceDatabase(tmp_path / "workspace")

    try:
        database.freeze_evidence(bundle)
        hashed = {
            line.split("  ", 1)[1]
            for line in (bundle / "hashes.sha256").read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        result = database.verify_workspace(bundle)

        assert "surface/.analysis-metadata" in hashed
        assert result["status"] == "ok"
        assert result["mismatches"] == []
        assert result["missing"] == []
        assert result["extra"] == []
    finally:
        _unfreeze(tmp_path / "workspace")


def test_freeze_makes_nested_evidence_directories_read_only(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    nested_evidence_dirs = [
        bundle / "apktool" / "smali" / "com" / "example",
        bundle / "surface" / "shards",
        bundle / "stages" / "surface",
    ]
    for path in nested_evidence_dirs:
        path.mkdir(parents=True)

    ai_analysis = bundle / "ai_analysis" / "attempt-01"
    ai_analysis.mkdir(parents=True)
    database = WorkspaceDatabase(tmp_path / "workspace")

    try:
        database.freeze_evidence(bundle)

        for path in [bundle / "apktool", *nested_evidence_dirs]:
            assert os.stat(path).st_mode & 0o222 == 0
        assert os.stat(ai_analysis).st_mode & 0o222
        assert database.verify_workspace(bundle)["writable"] == []
    finally:
        _unfreeze(tmp_path / "workspace")


def test_freeze_fails_and_removes_hash_manifest_when_file_chmod_fails(
    monkeypatch, tmp_path
):
    bundle = _make_bundle(tmp_path / "workspace")
    target = bundle / "surface" / "static-analysis.json"
    prior_files = [
        bundle / "apktool" / "AndroidManifest.xml",
        bundle / "surface" / "facts.jsonl",
    ]
    prior_modes = {path: stat.S_IMODE(path.stat().st_mode) for path in prior_files}
    database = WorkspaceDatabase(tmp_path / "workspace")
    real_chmod = os.chmod
    fail_once = True

    def fail_target_once(path, mode):
        nonlocal fail_once
        if Path(path) == target and fail_once:
            fail_once = False
            raise PermissionError("synthetic chmod failure")
        real_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", fail_target_once)

    with pytest.raises(DatabaseError, match="Cannot make frozen evidence read-only"):
        database.freeze_evidence(bundle)

    assert not (bundle / "hashes.sha256").exists()
    assert os.stat(target).st_mode & 0o222
    assert {
        path: stat.S_IMODE(path.stat().st_mode) for path in prior_files
    } == prior_modes


def test_verify_workspace_detects_writable_evidence(tmp_path):
    bundle = _make_bundle(tmp_path / "workspace")
    target_dir = bundle / "surface" / "shards"
    target_dir.mkdir()
    database = WorkspaceDatabase(tmp_path / "workspace")
    try:
        database.freeze_evidence(bundle)
        target_file = bundle / "surface" / "static-analysis.json"
        os.chmod(bundle / "surface", 0o755)
        os.chmod(target_file, 0o644)
        os.chmod(target_dir, 0o755)

        result = database.verify_workspace(bundle)

        assert result["status"] == "failed"
        assert {"path": "surface/static-analysis.json", "kind": "file"} in result["writable"]
        assert {"path": "surface", "kind": "directory"} in result["writable"]
        assert {"path": "surface/shards", "kind": "directory"} in result["writable"]
        os.chmod(bundle / "hashes.sha256", 0o644)
        result = database.verify_workspace(bundle)
        assert {"path": "hashes.sha256", "kind": "file"} in result["writable"]
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


def test_freeze_populates_missing_manifest_dir_and_verifies_ok(tmp_path):
    ws = tmp_path / "workspace"
    database = WorkspaceDatabase(ws)
    database.ensure()

    apk_dir = ws / "downloads" / "com.example.app-1"
    apk_dir.mkdir(parents=True)
    apk_path = apk_dir / "base.apk"
    apk_path.write_bytes(b"apk")
    bundle_manifest = {"source": "google_play", "package_id": "com.example.app", "version_code": 1}
    (apk_dir / "google-play-bundle.json").write_text(json.dumps(bundle_manifest), encoding="utf-8")
    database.append_history({
        "sha256": _BUNDLE_ID,
        "package_id": "com.example.app",
        "app_name": "Example",
        "version_code": "1",
        "version_name": "1.0",
        "source": "google_play",
        "download_url": "google-play://com.example.app/1/base.apk",
        "local_path": str(apk_path),
        "size": 3,
        "run_id": "run-freeze",
        "downloaded_at": "2026-11-23T00:00:00+00:00",
        "index_sha256": "a" * 64,
    })

    bundle = ws / "results" / "com.example.app" / "1" / _BUNDLE_ID
    (bundle / "apktool").mkdir(parents=True)
    (bundle / "apktool" / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (bundle / "surface").mkdir()
    (bundle / "surface" / "static-analysis.json").write_text("{}", encoding="utf-8")
    (bundle / "surface" / "facts.jsonl").write_text("", encoding="utf-8")
    (bundle / "surface" / "location_map.json").write_text("{}", encoding="utf-8")

    try:
        database.freeze_evidence(bundle)
        copied = bundle / "manifest" / "google-play-bundle.json"
        assert copied.is_file()
        assert json.loads(copied.read_text(encoding="utf-8")) == bundle_manifest
        result = database.verify_workspace(bundle)
        assert result["status"] == "ok"
        assert not os.stat(bundle / "manifest").st_mode & 0o222
    finally:
        _unfreeze(ws)


def test_freeze_populates_manifest_status_when_bundle_manifest_absent(tmp_path):
    ws = tmp_path / "workspace"
    database = WorkspaceDatabase(ws)
    bundle = ws / "results" / "com.example.app" / "1" / _BUNDLE_ID
    (bundle / "apktool").mkdir(parents=True)
    (bundle / "apktool" / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (bundle / "surface").mkdir()
    (bundle / "surface" / "static-analysis.json").write_text("{}", encoding="utf-8")

    try:
        database.freeze_evidence(bundle)
        status_file = bundle / "manifest" / "status.json"
        assert status_file.is_file()
        assert json.loads(status_file.read_text(encoding="utf-8"))["status"] == "not_present"
        assert database.verify_workspace(bundle)["status"] == "ok"
    finally:
        _unfreeze(ws)
