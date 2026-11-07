"""Tests for verified sequential decompilation."""
from __future__ import annotations

import csv
import hashlib
import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationError, DecompilationRunner


APK_BYTES = b"verified local apk fixture"


def add_download(database: WorkspaceDatabase, workspace: Path, *, payload=APK_BYTES):
    digest = hashlib.sha256(payload).hexdigest()
    apk_path = workspace / "downloads/org.example.app/7" / digest / "app.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(payload)
    database.append_history(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": 7,
            "version_name": "7.0",
            "source": "fdroid",
            "download_url": "https://f-droid.org/repo/app.apk",
            "local_path": str(apk_path),
            "size": len(payload),
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    return digest, apk_path


def make_runner(workspace):
    database = WorkspaceDatabase(workspace)
    database.ensure()
    digest, apk_path = add_download(database, workspace)
    runner = DecompilationRunner(
        database,
        workspace=workspace,
        jadx_executable="jadx",
        apktool_executable="apktool",
        timeout_seconds=30,
        logger=logging.getLogger("test-decompiler"),
    )
    return runner, database, digest, apk_path


def test_runs_jadx_then_apktool_with_single_worker(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        assert kwargs["timeout"] == 30
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    summary = runner.run()

    assert summary.examined == 1
    assert summary.completed == 1
    assert summary.failed == 0
    assert len(commands) == 2
    assert commands[0][0] == "jadx"
    assert commands[0][1:3] == ["--threads-count", "1"]
    assert commands[0][-1] == str(apk_path)
    assert commands[1][0:4] == ["apktool", "d", "--jobs", "1"]
    assert commands[1][-1] == str(apk_path)

    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "success"
    assert state["apktool_status"] == "success"
    assert state["scan_status"] == "pending"
    assert (tmp_path / "results/org.example.app/7" / digest / "jadx.log").is_file()
    assert (tmp_path / "results/org.example.app/7" / digest / "apktool.log").is_file()


def test_successful_artifact_is_skipped_on_subsequent_run(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "jadx_status": "success",
            "apktool_status": "success",
            "scan_status": "success",
            "error": "",
        }
    )

    def unexpected_run(*args, **kwargs):
        raise AssertionError("Decompiler should not be invoked for an already completed artifact")

    monkeypatch.setattr(subprocess, "run", unexpected_run)
    summary = runner.run()

    assert summary.examined == 0
    assert summary.skipped == 1
    assert database.read_processing_status()[digest]["scan_status"] == "success"


def test_modified_apk_is_rejected_before_decompilation(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)
    apk_path.write_bytes(b"modified after acquisition")

    def unexpected_run(*args, **kwargs):
        raise AssertionError("Decompiler must not receive modified APK bytes")

    monkeypatch.setattr(subprocess, "run", unexpected_run)
    summary = runner.run()

    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "failed"
    assert state["apktool_status"] == "failed"
    assert "SHA-256 changed" in state["error"]


def test_apktool_runs_even_when_jadx_fails_and_failure_is_recorded(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[0] == "jadx":
            return SimpleNamespace(returncode=9, stdout="", stderr="jadx error")
        return SimpleNamespace(returncode=0, stdout="apktool ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    summary = runner.run()

    assert summary.failed == 1
    assert [command[0] for command in commands] == ["jadx", "apktool"]
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "failed"
    assert state["apktool_status"] == "success"
    assert "jadx error" in state["error"]


def test_history_cannot_point_outside_download_workspace(monkeypatch, tmp_path):
    runner, database, digest, _apk_path = make_runner(tmp_path)
    outside = tmp_path / "outside.apk"
    outside.write_bytes(APK_BYTES)
    with database.history_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    row = rows[0]
    row["local_path"] = str(outside)
    with database.history_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerow(row)

    def unexpected_run(*args, **kwargs):
        raise AssertionError("Path outside downloads must not be processed")

    monkeypatch.setattr(subprocess, "run", unexpected_run)
    summary = runner.run()

    assert summary.failed == 1
    assert "outside the downloads workspace" in database.read_processing_status()[digest]["error"]



def test_stale_decompiler_output_symlink_is_unlinked_not_followed(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    output = tmp_path / "results/org.example.app/7" / ("a" * 64) / "jadx"
    output.parent.mkdir(parents=True)
    output.symlink_to(target, target_is_directory=True)

    DecompilationRunner._remove_existing_output(output)

    assert not output.exists()
    assert marker.read_text(encoding="utf-8") == "keep"


def test_decompiler_rejects_results_root_symlink_escape(tmp_path):
    runner, _database, _digest, _apk_path = make_runner(tmp_path)
    results = tmp_path / "results"
    results.rmdir()
    outside = tmp_path / "outside-results"
    outside.mkdir()
    results.symlink_to(outside, target_is_directory=True)

    with pytest.raises(DecompilationError, match="results directory resolves outside"):
        runner.run()
