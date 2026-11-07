"""Regression tests for bounded-memory decompiler subprocess logging."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationError, DecompilationRunner


def make_runner(tmp_path: Path) -> DecompilationRunner:
    return DecompilationRunner(
        WorkspaceDatabase(tmp_path),
        workspace=tmp_path,
        timeout_seconds=5,
        logger=logging.getLogger("test-decompiler-streaming"),
    )


def test_tool_output_is_streamed_to_disk_without_capture(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)
    log_path = tmp_path / "results" / "tool.log"
    emitted = b"tool output streamed to log\n"

    def fake_run(command, **kwargs):
        assert "capture_output" not in kwargs
        assert "stdout" in kwargs and kwargs["stdout"] is not subprocess.PIPE
        assert kwargs["stderr"] == subprocess.STDOUT
        assert kwargs["timeout"] == 5
        kwargs["stdout"].write(emitted)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner._run_tool(["example-tool", "input.apk"], log_path, "Example")

    contents = log_path.read_bytes()
    assert emitted in contents
    assert b"RETURN CODE: 0" in contents


def test_tool_timeout_is_recorded_in_log(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)
    log_path = tmp_path / "results" / "tool.log"

    def fake_run(command, **kwargs):
        kwargs["stdout"].write(b"partial output before timeout\n")
        raise subprocess.TimeoutExpired(command, timeout=5)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DecompilationError, match="exceeded the 5-second timeout"):
        runner._run_tool(["example-tool", "input.apk"], log_path, "Example")

    contents = log_path.read_bytes()
    assert b"partial output before timeout" in contents
    assert b"TIMEOUT AFTER: 5 seconds" in contents


def test_nonzero_exit_reports_bounded_log_tail(monkeypatch, tmp_path):
    runner = make_runner(tmp_path)
    log_path = tmp_path / "results" / "tool.log"

    def fake_run(command, **kwargs):
        kwargs["stdout"].write(b"x" * 5000 + b"final failure detail")
        return SimpleNamespace(returncode=9)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DecompilationError) as exc_info:
        runner._run_tool(["example-tool", "input.apk"], log_path, "Example")

    assert "final failure detail" in str(exc_info.value)
    assert len(str(exc_info.value)) < 3000
