from __future__ import annotations

import csv
import hashlib
import logging
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

import apkworkbench.cli.main as cli
from apkworkbench.core.config import Config
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.sources.google_play import (
    GooglePlayUnavailableError,
    PlayApp,
)


def _config(tmp_path):
    return Config(environ={
        "HOME": str(tmp_path),
        "APKWORKBENCH_WORKSPACE": str(tmp_path / "workspace"),
        "APKWORKBENCH_CONFIG_DIR": str(tmp_path / "config"),
        "APKWORKBENCH_STATE_DIR": str(tmp_path / "state"),
    })


def test_discover_writes_google_play_package_catalog(monkeypatch, tmp_path):
    config = _config(tmp_path)

    class FakeSource:
        def __init__(self, **_kwargs):
            pass

        def discover(self, **kwargs):
            assert kwargs["category_ids"] == ("FINANCE",)
            return [PlayApp("com.example.bank", "Example Bank", "Example Inc.", "1.0", 1)]

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "setup_logging", lambda _config: logging.getLogger("test-discover"))
    monkeypatch.setattr(cli, "GooglePlaySource", FakeSource)

    result = CliRunner().invoke(
        cli.main, ["discover", "--category", "FINANCE", "--limit", "10"]
    )

    assert result.exit_code == 0, result.output
    catalog = Path(config.get("workspace")) / "database/google_play_discovery.csv"
    with catalog.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["package_id"] == "com.example.bank"
    assert "GOOGLE PLAY STORE" in result.output


def test_download_skips_unavailable_apps_and_records_verified_play_artifact(monkeypatch, tmp_path):
    config = _config(tmp_path)
    catalog = cli._catalog_path(config)
    cli._write_catalog(catalog, [
        PlayApp("com.example.paid", "Paid App", "Example", "1.0", 1),
        PlayApp("com.example.free", "Free App", "Example", "2.0", 2),
    ])
    payload = b"verified google play apk"
    digest = hashlib.sha256(payload).hexdigest()
    app = PlayApp("com.example.free", "Free App", "Example", "2.0", 2)
    plan = SimpleNamespace(
        app=app,
        files=(SimpleNamespace(
            name="base.apk", kind="apk", sha256=digest, size=len(payload)
        ),),
        signer_sha256=("a" * 64,),
    )

    class FakeSource:
        def __init__(self, **_kwargs):
            pass

        def inspect(self, package_id):
            if package_id == "com.example.paid":
                raise GooglePlayUnavailableError("paid app")
            return plan

        def download(self, selected_plan, *, workspace, run_id):
            database = WorkspaceDatabase(workspace)
            frozen = database.read_manifest(run_id)
            assert frozen and frozen[0]["source"] == "google_play"
            directory = Path(workspace) / "downloads" / "com.example.free-2"
            directory.mkdir(parents=True, exist_ok=True)
            apk = directory / "base.apk"
            apk.write_bytes(payload)
            manifest = directory / "google-play-bundle.json"
            manifest.write_text('{"source":"google_play"}', encoding="utf-8")
            return SimpleNamespace(
                apk_files=(apk,), obb_files=(), manifest_path=manifest
            )

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "setup_logging", lambda _config: logging.getLogger("test-download"))
    monkeypatch.setattr(cli, "GooglePlaySource", FakeSource)

    result = CliRunner().invoke(cli.main, ["download", "--apk-count", "1"])

    assert result.exit_code == 0, result.output
    assert "SKIPPED (not downloadable" in result.output
    history = WorkspaceDatabase(config.get("workspace")).read_download_history()
    assert len(history) == 1
    assert history[0]["source"] == "google_play"
    assert history[0]["package_id"] == "com.example.free"
    assert history[0]["sha256"] == digest


def test_legacy_index_options_are_not_exposed():
    result = CliRunner().invoke(cli.main, ["discover", "--help"])
    assert result.exit_code == 0
    assert "--refresh-index" not in result.output

def test_exact_package_download_does_not_require_a_discovery_catalog(monkeypatch, tmp_path):
    config = _config(tmp_path)
    payload = b"single direct package apk"
    digest = hashlib.sha256(payload).hexdigest()
    app = PlayApp("com.example.direct", "Direct App", "Example", "1.0", 1)
    plan = SimpleNamespace(
        app=app,
        files=(SimpleNamespace(
            name="base.apk", kind="apk", sha256=digest, size=len(payload)
        ),),
        signer_sha256=(),
    )

    class FakeSource:
        def __init__(self, **_kwargs):
            pass

        def inspect(self, package_id):
            assert package_id == "com.example.direct"
            return plan

        def download(self, selected_plan, *, workspace, run_id):
            database = WorkspaceDatabase(workspace)
            assert database.read_manifest(run_id)
            directory = Path(workspace) / "downloads" / "com.example.direct-1"
            directory.mkdir(parents=True, exist_ok=True)
            apk = directory / "base.apk"
            apk.write_bytes(payload)
            manifest = directory / "google-play-bundle.json"
            manifest.write_text('{"source":"google_play"}', encoding="utf-8")
            return SimpleNamespace(apk_files=(apk,), obb_files=(), manifest_path=manifest)

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "setup_logging", lambda _config: logging.getLogger("test-direct"))
    monkeypatch.setattr(cli, "GooglePlaySource", FakeSource)

    result = CliRunner().invoke(
        cli.main, ["download", "--package", "com.example.direct"]
    )

    assert result.exit_code == 0, result.output
    history = WorkspaceDatabase(config.get("workspace")).read_download_history()
    assert len(history) == 1
    assert history[0]["package_id"] == "com.example.direct"



def test_discover_accepts_valid_package_ids_from_packages_file(monkeypatch, tmp_path):
    config = _config(tmp_path)
    packages_file = tmp_path / "packages.txt"
    packages_file.write_text(
        "com.example.bank\norg.example.wallet\n",
        encoding="utf-8",
    )

    class FakeSource:
        def __init__(self, **_kwargs):
            pass

        def discover(self, **_kwargs):
            return []

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "setup_logging", lambda _config: logging.getLogger("test-packages-file"))
    monkeypatch.setattr(cli, "GooglePlaySource", FakeSource)

    result = CliRunner().invoke(
        cli.main,
        ["discover", "--packages-file", str(packages_file), "--limit", "10"],
    )

    assert result.exit_code == 0, result.output
    catalog = Path(config.get("workspace")) / "database/google_play_discovery.csv"
    with catalog.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["package_id"] for row in rows] == [
        "com.example.bank",
        "org.example.wallet",
    ]


def test_discover_rejects_invalid_package_ids_from_packages_file(monkeypatch, tmp_path):
    config = _config(tmp_path)
    packages_file = tmp_path / "packages.txt"
    packages_file.write_text("com..example.bank\n", encoding="utf-8")

    class FakeSource:
        def __init__(self, **_kwargs):
            pass

        def discover(self, **_kwargs):
            return []

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "setup_logging", lambda _config: logging.getLogger("test-packages-file-invalid"))
    monkeypatch.setattr(cli, "GooglePlaySource", FakeSource)

    result = CliRunner().invoke(
        cli.main,
        ["discover", "--packages-file", str(packages_file), "--limit", "10"],
    )

    assert result.exit_code != 0
    assert "Invalid Android package ID" in result.output
    assert not (Path(config.get("workspace")) / "database/google_play_discovery.csv").exists()


def test_verify_downloads_command_reports_verified_files(monkeypatch, tmp_path):
    config = _config(tmp_path)
    called = {}

    def fake_verify(workspace, run_id, progress=None):
        called["workspace"] = workspace
        called["run_id"] = run_id
        return {
            "status": "verified",
            "verified_bundles": 1,
            "apk_components": 2,
            "obb_components": 1,
            "total_bytes": 12345,
            "report_path": str(tmp_path / "phase-one-report.json"),
            "bundles": [{
                "package_id": "com.example.bank",
                "version_code": 42,
                "apk_components": 2,
                "obb_components": 1,
                "directory": str(tmp_path / "downloads" / "com.example.bank-42"),
            }],
        }

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "verify_google_play_run", fake_verify)

    result = CliRunner().invoke(cli.main, ["verify-downloads", "--run-id", "phase-one-001"])

    assert result.exit_code == 0, result.output
    assert called == {"workspace": config.get("workspace"), "run_id": "phase-one-001"}
    assert "Status: VERIFIED" in result.output
    assert "APK components: 2" in result.output
    assert "OBB components: 1" in result.output


def test_full_run_continues_to_trufflehog_when_some_apktool_output_exists(monkeypatch, tmp_path):
    config = _config(tmp_path)
    calls = []

    def fake_download(apk_count, package_id):
        calls.append("download")
        __import__("click").get_current_context().meta["apkworkbench_run_id"] = "test-run"

    def fake_decompile(limit, force, run_id):
        calls.append("decompile")
        assert run_id == "test-run"
        raise __import__("click").exceptions.Exit(1)

    def fake_analyze(limit, force, run_id):
        calls.append("analyze")

    def fake_surface(database, workspace, *, run_id=None, force=False, progress=None):
        calls.append("surface")
        assert run_id == "test-run"
        return {
            "completed": 1, "failed": 0, "skipped": 0,
            "finding_count": 0,
        }

    def fake_report(run_id=None):
        calls.append("report")
        assert run_id == "test-run"

    def fake_verify(workspace, run_id, progress=None):
        calls.append("verify")
        assert run_id == "test-run"
        return {
            "verified_bundles": 1,
            "apk_components": 2,
            "obb_components": 0,
            "report_path": str(tmp_path / "verify.json"),
        }

    def fake_count(workspace, run_id):
        calls.append("count")
        assert run_id == "test-run"
        return 1

    monkeypatch.setattr(cli, "Config", lambda: config)
    monkeypatch.setattr(cli, "setup_logging", lambda _config: logging.getLogger("test-run"))
    monkeypatch.setattr(cli, "download", fake_download)
    monkeypatch.setattr(cli, "decompile", fake_decompile)
    monkeypatch.setattr(cli, "analyze", fake_analyze)
    monkeypatch.setattr(cli, "run_static_surface_analysis", fake_surface)
    monkeypatch.setattr(cli, "report", fake_report)
    monkeypatch.setattr(cli, "verify_google_play_run", fake_verify)
    monkeypatch.setattr(cli, "_count_usable_apktool_outputs", fake_count)
    monkeypatch.setattr(
        WorkspaceDatabase,
        "reconcile_run",
        lambda self, run_id: {
            "total": 1,
            "complete": 1,
            "counts": {"complete": 1},
        },
    )

    result = CliRunner().invoke(cli.main, ["run", "--apk-count", "1"])

    assert result.exit_code == 1, result.output
    assert calls == ["download", "verify", "decompile", "count", "surface", "count", "analyze", "report"]
    assert "Continuing to TruffleHog for those artifacts" in result.output
    assert "Starting TruffleHog for 1 APK(s) with saved Apktool output" in result.output
