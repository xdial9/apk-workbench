"""Tests for the run command's strict stage ordering and error continuation."""
from __future__ import annotations

import importlib
from contextlib import nullcontext

import click
from click.testing import CliRunner


cli = importlib.import_module("apkworkbench.cli.main")


def make_stage_command(name, calls, *, exit_code=0):
    def callback(**kwargs):
        calls.append((name, kwargs))
        if name == "download":
            click.get_current_context().meta["apkworkbench_run_id"] = "run-123"
        if exit_code:
            raise click.exceptions.Exit(exit_code)

    if name == "download":
        params = [
            click.Option(["--apk-count"], type=int),
            click.Option(["--package"], default=None),
            click.Option(["--refresh-index"], is_flag=True),
        ]
    elif name in {"decompile", "analyze"}:
        params = [
            click.Option(["--limit"], type=int),
            click.Option(["--force"], is_flag=True),
            click.Option(["--run-id"], default=None),
        ]
    else:
        params = []
    return click.Command(name, callback=callback, params=params)


def install_reconciliation_stub(monkeypatch, *, complete: bool):
    class FakeConfig:
        def get(self, key, default=None):
            return "/tmp/apk-workbench-test" if key == "workspace" else default

    class FakeDatabase:
        def __init__(self, _workspace):
            pass

        def _write_lock(self):
            return nullcontext()

        def reconcile_run(self, run_id):
            assert run_id == "run-123"
            return {
                "total": 1,
                "complete": int(complete),
                "counts": {"complete": 1} if complete else {"download_failed": 1},
            }

    monkeypatch.setattr(cli, "Config", FakeConfig)
    monkeypatch.setattr(cli, "WorkspaceDatabase", FakeDatabase)


def test_run_invokes_all_stages_in_order_and_continues_after_download_shortfall(monkeypatch):
    install_reconciliation_stub(monkeypatch, complete=False)
    calls = []
    monkeypatch.setattr(
        cli, "download", make_stage_command("download", calls, exit_code=2)
    )
    monkeypatch.setattr(cli, "decompile", make_stage_command("decompile", calls))
    monkeypatch.setattr(cli, "analyze", make_stage_command("analyze", calls))
    monkeypatch.setattr(cli, "report", make_stage_command("report", calls))

    result = CliRunner().invoke(
        cli.main,
        ["run", "--apk-count", "3", "--package", "org.example.app"],
    )

    assert result.exit_code == 1
    assert [name for name, _kwargs in calls] == [
        "download",
        "decompile",
        "analyze",
        "report",
    ]
    assert "Stage download ended with exit code 2" in result.output
    assert "Stages requiring attention: download" in result.output
    assert calls[0][1]["apk_count"] == 3
    assert calls[0][1]["package_id"] == "org.example.app"
    assert calls[1][1]["run_id"] == "run-123"
    assert calls[2][1]["run_id"] == "run-123"


def test_run_returns_success_when_all_stages_finish_without_errors(monkeypatch):
    install_reconciliation_stub(monkeypatch, complete=True)
    calls = []
    monkeypatch.setattr(cli, "download", make_stage_command("download", calls))
    monkeypatch.setattr(cli, "decompile", make_stage_command("decompile", calls))
    monkeypatch.setattr(cli, "analyze", make_stage_command("analyze", calls))
    monkeypatch.setattr(cli, "report", make_stage_command("report", calls))

    result = CliRunner().invoke(
        cli.main, ["run", "--apk-count", "1", "--refresh-index"]
    )

    assert result.exit_code == 0, result.output
    assert [name for name, _kwargs in calls] == [
        "download",
        "decompile",
        "analyze",
        "report",
    ]
    assert calls[1][1]["run_id"] == "run-123"
    assert calls[2][1]["run_id"] == "run-123"
    assert calls[0][1]["refresh_index"] is True
    assert "All pipeline stages completed without reported errors." in result.output
