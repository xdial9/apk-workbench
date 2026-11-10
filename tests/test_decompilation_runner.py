"""Regression tests for Apktool-only safe, retryable, bounded-memory decompilation."""
from __future__ import annotations

import csv
import hashlib
import logging
import signal
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
            "source": "google_play",
            "download_url": "google-play://fixture/app.apk",
            "local_path": str(apk_path),
            "size": len(payload),
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    return digest, apk_path


def output_path(command: list[str]) -> Path:
    return Path(command[command.index("-o") + 1])


def make_runner(workspace: Path):
    database = WorkspaceDatabase(workspace)
    database.ensure()
    digest, apk_path = add_download(database, workspace)
    runner = DecompilationRunner(
        database,
        workspace=workspace,
        apktool_executable="apktool",
        timeout_seconds=30,
        logger=logging.getLogger("test-apktool"),
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


def successful_tool(command, kwargs, text="decoded output"):
    kwargs["stdout"].write(b"apktool output\n")
    destination = output_path(command)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "AndroidManifest.xml").write_text(text, encoding="utf-8")


def test_runs_only_apktool_and_preserves_jobs_parameter(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)
    calls = install_fake_popen(monkeypatch, successful_tool)

    summary = runner.run()

    assert summary.examined == summary.completed == 1
    assert summary.failed == summary.partial == 0
    assert len(calls) == 1
    command = calls[0]
    assert command[0] == "apktool"
    assert command[1:4] == ["d", "--jobs", "4"]
    assert command[4:6] == ["--force", "-o"]
    assert command[-1] == str(apk_path)
    assert not any("jadx" in str(part).lower() for part in command)
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "not_used"
    assert state["apktool_status"] == "success"
    assert state["scan_status"] == "pending"
    log = (tmp_path / "results/org.example.app/7" / digest / "apktool.log").read_bytes()
    assert b"STDOUT AND STDERR (combined)" in log
    assert b"RETURN CODE: 0" in log


def test_successful_output_is_skipped_and_legacy_jadx_failure_is_ignored(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    output = tmp_path / "results/org.example.app/7" / digest / "apktool"
    output.mkdir(parents=True)
    (output / "AndroidManifest.xml").write_text("existing", encoding="utf-8")
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "jadx_status": "failed",
            "apktool_status": "success",
            "scan_status": "pending",
            "error": "legacy JADX failure",
        }
    )
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("reusable Apktool output must not rerun")
    )

    summary = runner.run()

    assert summary.examined == 0
    assert summary.skipped == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "not_used"
    assert state["apktool_status"] == "success"


def test_modified_apk_is_rejected_before_tool_execution(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)
    apk_path.write_bytes(b"modified after acquisition")
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("modified APK reached Apktool")
    )

    summary = runner.run()

    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "not_used"
    assert state["apktool_status"] == "failed"
    assert "SHA-256 changed" in state["error"]


def test_apktool_failure_is_recorded_and_no_other_decompiler_is_called(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    calls = []

    def failed(command, **kwargs):
        calls.append(command[0])
        kwargs["stdout"].write(b"Apktool failed")
        return FakeProcess(9)

    monkeypatch.setattr(subprocess, "Popen", failed)
    summary = runner.run()

    assert calls == ["apktool"]
    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "not_used"
    assert state["apktool_status"] == "failed"
    assert "Apktool exited with status 9" in state["error"]


def test_retry_reexecutes_only_apktool(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda command, **kwargs: (kwargs["stdout"].write(b"first Apktool attempt failed"), FakeProcess(7))[1],
    )
    assert runner.run().failed == 1

    calls = []

    def success(command, **kwargs):
        calls.append(command[0])
        successful_tool(command, kwargs, "retried Apktool output")
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", success)
    summary = runner.run()

    assert summary.completed == 1
    assert summary.failed == 0
    assert calls == ["apktool"]
    output = tmp_path / "results/org.example.app/7" / digest / "apktool/AndroidManifest.xml"
    assert output.read_text(encoding="utf-8") == "retried Apktool output"
    assert database.read_processing_status()[digest]["jadx_status"] == "not_used"


def test_failed_forced_refresh_preserves_previous_good_output(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    install_fake_popen(
        monkeypatch, lambda command, kwargs: successful_tool(command, kwargs, "known good")
    )
    assert runner.run().completed == 1
    output = tmp_path / "results/org.example.app/7" / digest / "apktool/AndroidManifest.xml"

    def failed_refresh(command, **kwargs):
        kwargs["stdout"].write(b"forced refresh failed")
        return FakeProcess(9)

    monkeypatch.setattr(subprocess, "Popen", failed_refresh)
    summary = runner.run(force=True)

    assert summary.failed == 1
    assert output.read_text(encoding="utf-8") == "known good"
    state = database.read_processing_status()[digest]
    assert state["apktool_status"] == "success"
    assert "Apktool exited with status 9" in state["error"]


def test_zero_exit_without_usable_output_fails(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProcess(0))

    summary = runner.run()

    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "not_used"
    assert state["apktool_status"] == "failed"
    assert "no usable output" in state["error"]


def test_apktool_exit_code_three_is_not_partial_success(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)

    def nonzero(command, **kwargs):
        successful_tool(command, kwargs, "decoded but nonzero")
        return FakeProcess(3)

    monkeypatch.setattr(subprocess, "Popen", nonzero)
    summary = runner.run()

    assert summary.failed == 1
    state = database.read_processing_status()[digest]
    assert state["apktool_status"] == "failed"
    assert state["jadx_status"] == "not_used"


def test_timeout_logs_and_terminates_process_group(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)[0]
    log_path = tmp_path / "results/tool.log"
    terminated = []

    class TimedOut(FakeProcess):
        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(["apktool"], timeout)

    def spawn(command, **kwargs):
        kwargs["stdout"].write(b"partial output before timeout")
        return TimedOut()

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(
        runner, "_terminate_process_tree", lambda process: terminated.append(process.pid)
    )

    with pytest.raises(DecompilationError, match="exceeded the 30-second timeout"):
        runner._run_tool(["apktool", "d"], log_path, "Apktool")

    assert terminated == [424242]
    contents = log_path.read_bytes()
    assert b"partial output before timeout" in contents
    assert b"TIMEOUT AFTER: 30 seconds" in contents


def test_download_history_cannot_escape_workspace(monkeypatch, tmp_path):
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
        subprocess, "Popen", lambda *a, **k: pytest.fail("unsafe path reached Apktool")
    )

    summary = runner.run()

    assert summary.failed == 1
    assert "outside the downloads workspace" in database.read_processing_status()[digest]["error"]


def test_results_root_symlink_escape_is_rejected(tmp_path):
    runner = make_runner(tmp_path)[0]
    results = tmp_path / "results"
    results.mkdir()
    results.rmdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-results"
    outside.mkdir()
    results.symlink_to(outside, target_is_directory=True)

    with pytest.raises(DecompilationError, match="results directory resolves outside"):
        runner.run()


def test_manifest_scope_limits_apktool_to_selected_artifact(monkeypatch, tmp_path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    digest, apk_path = add_download(database, tmp_path, b"selected APK")
    row = {
        "run_id": "selected-run",
        "selection_order": 1,
        "selected_at": "2026-11-07T12:00:00+00:00",
        "package_id": "org.example.app",
        "app_name": "Example",
        "version_code": 7,
        "version_name": "7.0",
        "source": "google_play",
        "download_url": "google-play://fixture/app.apk",
        "sha256": digest,
        "size": apk_path.stat().st_size,
        "signer_sha256": "",
        "local_path": str(apk_path),
        "index_sha256": "f" * 64,
    }
    with database.history_path.open(encoding="utf-8", newline="") as handle:
        history = list(csv.DictReader(handle))
    history[0]["run_id"] = "selected-run"
    with database.history_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=history[0].keys())
        writer.writeheader()
        writer.writerow(history[0])
    database.write_manifest("selected-run", [row])

    runner = DecompilationRunner(database, workspace=tmp_path)
    calls = []

    def spawn(command, **kwargs):
        calls.append(command[-1])
        successful_tool(command, kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", spawn)
    summary = runner.run(run_id="selected-run")

    assert summary.completed == 1
    assert summary.failed == 0
    assert calls == [str(apk_path)]


def test_stale_output_symlink_removal_does_not_follow_target(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    output = tmp_path / "results/org.example.app/7" / ("a" * 64) / "apktool"
    output.parent.mkdir(parents=True)
    output.symlink_to(target, target_is_directory=True)

    DecompilationRunner._remove_existing_output(output)

    assert not output.exists()
    assert marker.read_text(encoding="utf-8") == "keep"


def test_package_output_symlink_is_rejected(tmp_path):
    runner = make_runner(tmp_path)[0]
    package_root = tmp_path / "results/org.example.app"
    package_root.mkdir(parents=True, exist_ok=True)
    package_root.rename(tmp_path / "results/original-package")
    package_root.symlink_to(
        tmp_path / "results/original-package", target_is_directory=True
    )

    with pytest.raises(DecompilationError, match="symlinked workspace component"):
        runner.run()


def test_staged_output_log_symlink_is_not_followed(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    output_root = tmp_path / "results/org.example.app/7" / digest
    output_root.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.log"
    outside.write_text("preserve", encoding="utf-8")
    (output_root / "apktool.log").symlink_to(outside)
    install_fake_popen(monkeypatch, successful_tool)

    summary = runner.run()

    assert summary.failed == 1
    assert outside.read_text(encoding="utf-8") == "preserve"
    assert (output_root / "apktool.log").is_symlink()
    assert database.read_processing_status()[digest]["apktool_status"] == "failed"


def test_process_group_termination_escalates_from_term_to_kill(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)[0]
    signals = []

    class Stubborn:
        pid = 515151

        def __init__(self):
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(["apktool"], timeout)
            return -signal.SIGKILL

    process = Stubborn()
    monkeypatch.setattr(
        "apkworkbench.decompilation.runner.os.killpg",
        lambda _pid, signum: signals.append(signum),
    )
    runner._terminate_process_tree(process)
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert process.calls == 2


def test_apktool_runs_even_when_legacy_jadx_status_is_failed(monkeypatch, tmp_path):
    runner, database, digest, _ = make_runner(tmp_path)
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "jadx_status": "failed",
            "apktool_status": "pending",
            "scan_status": "pending",
            "error": "Historical JADX failure must not block Apktool.",
        }
    )
    calls = []

    def spawn(command, **kwargs):
        calls.append(command[0])
        successful_tool(command, kwargs, "fresh Apktool output")
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", spawn)
    summary = runner.run()

    assert summary.completed == 1
    assert summary.failed == 0
    assert calls == ["apktool"]
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == "not_used"
    assert state["apktool_status"] == "success"
    assert state["error"] == ""


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
        subprocess, "Popen", lambda *args, **kwargs: pytest.fail("invalid record reached Apktool")
    )
    summary = runner.run()

    assert summary.examined == 0
    assert summary.failed == 1
    assert summary.skipped == 0


def test_keyboard_interrupt_terminates_apktool_process_group(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)[0]
    log_path = tmp_path / "results/tool.log"
    terminated = []

    class InterruptedProcess(FakeProcess):
        def wait(self, timeout=None):
            raise KeyboardInterrupt()

    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: InterruptedProcess()
    )
    monkeypatch.setattr(
        runner,
        "_terminate_process_tree",
        lambda process: terminated.append(process.pid),
    )

    with pytest.raises(KeyboardInterrupt):
        runner._run_tool(["apktool", "d", "input.apk"], log_path, "Apktool")

    assert terminated == [424242]
    assert b"INTERRUPTED: process group terminated" in log_path.read_bytes()

