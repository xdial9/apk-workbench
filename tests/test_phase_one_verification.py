from __future__ import annotations

import hashlib
import json

import pytest

from apkworkbench.acquisition.verification import (
    AcquisitionVerificationError,
    verify_google_play_run,
)
from apkworkbench.database.workspace import WorkspaceDatabase


def _digest(content: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, content).hexdigest()


def _make_run(tmp_path):
    workspace = tmp_path / "workspace"
    run_id = "phase-one-test-001"
    bundle_dir = workspace / "downloads" / "org.example.app-1"
    bundle_dir.mkdir(parents=True)

    base_bytes = b"synthetic-base-apk-fixture"
    obb_bytes = b"synthetic-obb-fixture"
    (bundle_dir / "base.apk").write_bytes(base_bytes)
    (bundle_dir / "main.1.org.example.app.obb").write_bytes(obb_bytes)

    bundle = {
        "source": "google_play",
        "package_id": "org.example.app",
        "title": "Example",
        "developer": "Example Developer",
        "version_name": "1.0",
        "version_code": 1,
        "run_id": run_id,
        "files": [
            {
                "name": "base.apk",
                "kind": "apk",
                "size": len(base_bytes),
                "sha256": _digest(base_bytes, "sha256"),
                "play_hash_algorithm": "sha256",
                "play_hash": _digest(base_bytes, "sha256"),
                "play_hash_verified": True,
            },
            {
                "name": "main.1.org.example.app.obb",
                "kind": "obb",
                "size": len(obb_bytes),
                "sha256": _digest(obb_bytes, "sha256"),
                "play_hash_algorithm": "sha1",
                "play_hash": _digest(obb_bytes, "sha1"),
                "play_hash_verified": True,
            },
        ],
    }
    (bundle_dir / "google-play-bundle.json").write_text(
        json.dumps(bundle), encoding="utf-8"
    )

    database = WorkspaceDatabase(workspace)
    database.write_manifest(
        run_id,
        [
            {
                "run_id": run_id,
                "selection_order": 1,
                "selected_at": "2026-11-08T00:00:00+00:00",
                "package_id": "org.example.app",
                "app_name": "Example",
                "version_code": 1,
                "version_name": "1.0",
                "source": "google_play",
                "download_url": "google-play://org.example.app/1/base.apk",
                "sha256": _digest(base_bytes, "sha256"),
                "size": len(base_bytes),
                "signer_sha256": "",
                "local_path": str(bundle_dir / "base.apk"),
                "index_sha256": "0" * 64,
            }
        ],
    )
    return workspace, run_id, bundle_dir


def test_verifies_all_apk_and_obb_files_and_writes_report(tmp_path):
    workspace, run_id, _ = _make_run(tmp_path)

    summary = verify_google_play_run(workspace, run_id)

    assert summary["status"] == "verified"
    assert summary["verified_bundles"] == 1
    assert summary["manifest_apk_records"] == 1
    assert summary["apk_components"] == 1
    assert summary["obb_components"] == 1
    assert summary["total_bytes"] > 0
    assert (workspace / "reports" / f"phase_one_verification_{run_id}.json").is_file()


def test_rejects_changed_apk_bytes(tmp_path):
    workspace, run_id, bundle_dir = _make_run(tmp_path)
    (bundle_dir / "base.apk").write_bytes(b"modified")

    with pytest.raises(AcquisitionVerificationError, match="Size mismatch|SHA-256 mismatch"):
        verify_google_play_run(workspace, run_id)


def test_rejects_unverified_play_component_digest(tmp_path):
    workspace, run_id, bundle_dir = _make_run(tmp_path)
    bundle_path = bundle_dir / "google-play-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["files"][1]["play_hash_verified"] = False
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(AcquisitionVerificationError, match="not marked verified"):
        verify_google_play_run(workspace, run_id)


def test_rejects_leftover_partial_component(tmp_path):
    workspace, run_id, bundle_dir = _make_run(tmp_path)
    (bundle_dir / "base.apk.part").write_bytes(b"incomplete")

    with pytest.raises(AcquisitionVerificationError, match="Unfinished partial download"):
        verify_google_play_run(workspace, run_id)


def test_rejects_bundle_manifest_for_a_different_run(tmp_path):
    workspace, run_id, bundle_dir = _make_run(tmp_path)
    bundle_path = bundle_dir / "google-play-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["run_id"] = "another-run"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(AcquisitionVerificationError, match="identity does not match"):
        verify_google_play_run(workspace, run_id)
