"""Regression tests for safe, retryable, bounded-memory decompilation."""
from __future__ import annotations

import csv
import hashlib
import logging
import subprocess
from pathlib import Path

import pytest

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationError, DecompilationRunner


APK_BYTES = b"verified local apk fixture"


class FakeProcess:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.pid = 424242

    def wait(self, timeout=None):
        return self.returncode


def add_download(database: WorkspaceDatabase, workspace: Path, payload: bytes = APK_BYTES):
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


def output_path(command: list[str]) -> Path:
    flag = "--output-dir" if command[0] == "jadx" else "-o"
    return Path(command[command.index(flag) + 1])


def make_runner(workspace: Path):
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


def install_fake_popen(monkeypatch, behavior):
    calls = []

    def fake_popen(command, **kwargs):
        calls.append(command)
        assert kwargs["stderr"] == subprocess.STDOUT
        assert kwargs["start_new_session"] is True
        assert kwargs["stdout"] is not subprocess.PIPE
        behavior(command, kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls


def successful_tool(command, kwargs, text="decompiled output"):
    kwargs["stdout"].write(f"{command[0]} output\n".encode())
    destination = output_path(command)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "fixture.txt").write_text(text, encoding="utf-8")


def test_runs_jadx_then_apktool_streaming_to_disk(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)

    def behavior(command, kwargs):
        successful_tool(command, kwargs, command[0])

    calls = install_fake_popen(monkeypatch, behavior)
    summary = runner.run()

    assert summary.examined == summary.completed == 1
    assert summary.failed == 0
    assert [command[0] for command in calls] == ["jadx", "apktool"]
    assert calls[0][1:3] == ["--threads-count", "1"]
    assert calls[0][-1] == str(apk_path)
    assert calls[1][1:4] == ["d", "--jobs", "1"]
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == state["apktool_status"] == "success"
    assert state["scan_status"] == "pending"
    for name in ("jadx.log", "apktool.log"):
        log = (tmp_path / "results/org.example.app/7" / digest / name).read_bytes()
        assert b"STDOUT AND STDERR (combined)" in log
        assert b"output" in log
        assert b"RETURN CODE: 0" in log


def test_successful_artifact_is_skipped_when_outputs_still_exist(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    root = tmp_path / "results/org.example.app/7" / digest
    for name in ("jadx", "apktool"):
        output = root / name
        output.mkdir(parents=True)
        (output / "fixture.txt").write_text("existing", encoding="utf-8")
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

    def unexpected(*args, **kwargs):
        raise AssertionError("completed tools must not be rerun")

    monkeypatch.setattr(subprocess, "Popen", unexpected)
    summary = runner.run()
    assert summary.examined == 0
    assert summary.skipped == 1


def test_modified_apk_is_rejected_before_subprocess(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)
    apk_path.write_bytes(b"modified after acquisition")

    def unexpected(*args, **kwargs):
        raise AssertionError("modified APK must not reach a decompiler")

    monkeypatch.setattr(subprocess, "Popen", unexpected)
    summary = runner.run()
    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == state["apktool_status"] == "failed"
    assert "SHA-256 changed" in state["error"]


def test_apktool_runs_even_when_jadx_fails(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    calls = []

    def fake_popen(command, **kwargs):
        calls.append(command[0])
        if command[0] == "jadx":
            kwargs["stdout"].write(b"JADX failed with exit 9")
            return FakeProcess(9)
        successful_tool(command, kwargs, "apktool output")
        return FakeProcess(0)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    summary = runner.run()
    assert summary.failed == 1
    assert calls == ["jadx", "apktool"]
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "failed"
    assert state["apktool_status"] == "success"
    assert "JADX exited with status 9" in state["error"]


def test_retry_only_reexecutes_the_failed_tool(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    first_calls = []

    def first(command, kwargs):
        first_calls.append(command[0])
        if command[0] == "jadx":
            successful_tool(command, kwargs, "original JADX")
        else:
            kwargs["stdout"].write(b"Apktool failed")
            # A nonzero process result is selected by the process factory below.

    def first_popen(command, **kwargs):
        first(command, kwargs)
        return FakeProcess(7 if command[0] == "apktool" else 0)

    monkeypatch.setattr(subprocess, "Popen", first_popen)
    assert runner.run().failed == 1
    assert first_calls == ["jadx", "apktool"]
    jadx_output = tmp_path / "results/org.example.app/7" / digest / "jadx"
    assert (jadx_output / "fixture.txt").read_text(encoding="utf-8") == "original JADX"

    second_calls = []

    def retry(command, kwargs):
        second_calls.append(command[0])
        assert command[0] == "apktool"
        successful_tool(command, kwargs, "retried Apktool")

    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda command, **kwargs: (retry(command, kwargs), FakeProcess())[1],
    )
    summary = runner.run()
    assert summary.completed == 1
    assert summary.failed == 0
    assert second_calls == ["apktool"]
    assert (jadx_output / "fixture.txt").read_text(encoding="utf-8") == "original JADX"


def test_failed_forced_refresh_preserves_previous_successful_output(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)

    def initial(command, kwargs):
        successful_tool(command, kwargs, f"original {command[0]}")

    install_fake_popen(monkeypatch, initial)
    assert runner.run().completed == 1
    root = tmp_path / "results/org.example.app/7" / digest
    jadx_output = root / "jadx"

    def refresh(command, **kwargs):
        if command[0] == "jadx":
            kwargs["stdout"].write(b"forced refresh failed")
            return FakeProcess(9)
        successful_tool(command, kwargs, "replacement Apktool")
        return FakeProcess(0)

    monkeypatch.setattr(subprocess, "Popen", refresh)
    summary = runner.run(force=True)
    assert summary.failed == 1
    assert (jadx_output / "fixture.txt").read_text(encoding="utf-8") == "original jadx"
    assert (root / "apktool/fixture.txt").read_text(encoding="utf-8") == "replacement Apktool"
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == state["apktool_status"] == "success"
    assert "JADX exited with status 9" in state["error"]


def test_zero_exit_without_usable_output_is_failure(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProcess(0))
    summary = runner.run()
    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == state["apktool_status"] == "failed"
    assert "no usable output" in state["error"]


def test_timeout_is_logged_and_process_group_termination_is_attempted(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)[0]
    log_path = tmp_path / "results/tool.log"
    terminated = []

    class TimedOutProcess(FakeProcess):
        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(["example-tool"], timeout)

    def fake_popen(command, **kwargs):
        kwargs["stdout"].write(b"partial output before timeout")
        assert kwargs["start_new_session"] is True
        return TimedOutProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        runner,
        "_terminate_process_tree",
        lambda process: terminated.append(process.pid),
    )
    with pytest.raises(DecompilationError, match="exceeded the 30-second timeout"):
        runner._run_tool(["example-tool", "input.apk"], log_path, "Example")
    assert terminated == [424242]
    contents = log_path.read_bytes()
    assert b"partial output before timeout" in contents
    assert b"TIMEOUT AFTER: 30 seconds" in contents


def test_history_cannot_point_outside_download_workspace(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    outside = tmp_path / "outside.apk"
    outside.write_bytes(APK_BYTES)
    with database.history_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[0]["local_path"] = str(outside)
    with database.history_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerow(rows[0])
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("unsafe path reached subprocess")
    )
    summary = runner.run()
    assert summary.failed == 1
    assert "outside the downloads workspace" in database.read_processing_status()[digest]["error"]


def test_stale_output_symlink_is_unlinked_without_following(tmp_path):
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


def test_results_root_symlink_escape_is_rejected(tmp_path):
    runner, _, _, _ = make_runner(tmp_path)
    results = tmp_path / "results"
    results.mkdir()
    results.rmdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-results"
    outside.mkdir()
    results.symlink_to(outside, target_is_directory=True)
    with pytest.raises(DecompilationError, match="results directory resolves outside"):
        runner.run()


def test_run_id_limits_processing_to_frozen_manifest(monkeypatch, tmp_path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()

    def add_run_artifact(run_id: str, payload: bytes):
        digest = hashlib.sha256(payload).hexdigest()
        apk_path = tmp_path / "downloads/org.example.app/7" / digest / "app.apk"
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
                "run_id": run_id,
                "downloaded_at": "2026-11-07T12:00:00+00:00",
                "index_sha256": "f" * 64,
            }
        )
        database.write_manifest(
            run_id,
            [{
                "run_id": run_id,
                "selection_order": 1,
                "selected_at": "2026-11-07T12:00:00+00:00",
                "package_id": "org.example.app",
                "app_name": "Example",
                "version_code": 7,
                "version_name": "7.0",
                "source": "fdroid",
                "download_url": "https://f-droid.org/repo/app.apk",
                "sha256": digest,
                "size": len(payload),
                "signer_sha256": "",
                "local_path": str(apk_path),
                "index_sha256": "f" * 64,
            }],
        )
        return digest, apk_path

    old_digest, _ = add_run_artifact("old-run", b"old apk")
    selected_digest, selected_path = add_run_artifact("new-run", b"new apk")
    runner = DecompilationRunner(database, workspace=tmp_path)
    calls = []

    def fake_popen(command, **kwargs):
        calls.append(command[-1])
        successful_tool(command, kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    summary = runner.run(run_id="new-run")
    assert summary.examined == summary.completed == 1
    assert summary.failed == 0
    assert calls == [str(selected_path), str(selected_path)]
    assert database.read_processing_status()[selected_digest]["jadx_status"] == "success"
    assert old_digest not in database.read_processing_status()


def test_malformed_history_digest_is_counted_as_failed(monkeypatch, tmp_path):
    runner, database, _digest, _ = make_runner(tmp_path)
    with database.history_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    rows[0]["sha256"] = ""
    with database.history_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerow(rows[0])

    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("invalid record reached tool")
    )
    summary = runner.run()
    assert summary.examined == 0
    assert summary.failed == 1
    assert summary.skipped == 0
