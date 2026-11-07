"""CLI tests for inspecting incomplete and completed acquisition runs."""
from __future__ import annotations

import importlib
from click.testing import CliRunner

cli = importlib.import_module("apkworkbench.cli.main")
from apkworkbench.database.workspace import WorkspaceDatabase


def test_reconcile_command_reports_unresolved_then_complete_run(monkeypatch, tmp_path):
    run_id = "cli-reconcile"
    digest = "a" * 64
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    selected = {
        "run_id": run_id,
        "selection_order": 1,
        "selected_at": "2026-11-07T12:00:00+00:00",
        "package_id": "org.example.cli",
        "app_name": "CLI Fixture",
        "version_code": 1,
        "version_name": "1.0",
        "source": "google_play",
        "download_url": "google-play://fixture/cli.apk",
        "sha256": digest,
        "size": 10,
        "signer_sha256": "",
        "local_path": str(tmp_path / "downloads/cli.apk"),
        "index_sha256": "b" * 64,
    }
    database.write_manifest(run_id, [selected])

    class ConfigStub:
        def get(self, key, default=None):
            return str(tmp_path) if key == "workspace" else default

    monkeypatch.setattr(cli, "Config", ConfigStub)
    runner = CliRunner()

    incomplete = runner.invoke(cli.main, ["reconcile", "--run-id", run_id])
    assert incomplete.exit_code == 1
    assert "acquisition_unaccounted: 1" in incomplete.output
    assert "UNRESOLVED ITEMS" in incomplete.output

    database.append_history(
        {
            **selected,
            "downloaded_at": "2026-11-07T12:00:00+00:00",
        }
    )
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.cli",
            "version_code": "1",
            "jadx_status": "success",
            "apktool_status": "success",
            "scan_status": "success",
            "error": "",
        }
    )

    complete = runner.invoke(cli.main, ["reconcile", "--run-id", run_id])
    assert complete.exit_code == 0
    assert "Complete: 1" in complete.output
    assert "All manifest items have a complete terminal outcome." in complete.output
