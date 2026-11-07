"""Tests for the TruffleHog wrapper's no-verification and redaction guarantees."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import subprocess
from pathlib import Path

from apkworkbench.analysis.trufflehog import TruffleHogScanner
from apkworkbench.database.workspace import WorkspaceDatabase


RAW_SECRET = "AKIAIOSFODNN7EXAMPLE"
HELP_TEXT = (
    "filesystem command help --no-verification --no-update --json "
    "--concurrency --fail-on-scan-errors"
)


class FakeProcess:
    def __init__(self, return_code: int = 0):
        self.return_code = return_code
        self.killed = False

    def wait(self, timeout=None):
        return self.return_code

    def kill(self):
        self.killed = True


def result_json(raw=RAW_SECRET):
    return {
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "/workspace/results/org.example.app/7/jadx/sources/Config.java",
                    "line": 23,
                }
            }
        },
        "SourceID": 0,
        "SourceType": 15,
        "SourceName": "trufflehog - filesystem",
        "DetectorType": 2,
        "DetectorName": "AWS",
        "DecoderName": "PLAIN",
        "Verified": False,
        "Raw": raw,
        "RawV2": "secret-part",
        "Redacted": "AKIA...EXAMPLE",
        "ExtraData": {"account": "123456789012", "sensitive": "do-not-store"},
    }


def make_workspace(tmp_path: Path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    apk = tmp_path / "downloads/org.example.app/7/app.apk"
    apk.parent.mkdir(parents=True, exist_ok=True)
    apk.write_bytes(b"downloaded apk")
    digest = hashlib.sha256(b"downloaded apk").hexdigest()
    database.append_history(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": 7,
            "version_name": "7.0",
            "source": "fdroid",
            "download_url": "https://f-droid.org/repo/app.apk",
            "local_path": str(apk),
            "size": len(b"downloaded apk"),
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    for tool in ("jadx", "apktool"):
        directory = tmp_path / "results/org.example.app/7" / tool
        directory.mkdir(parents=True)
        (directory / "placeholder.txt").write_text("source code", encoding="utf-8")
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "jadx_status": "success",
            "apktool_status": "success",
            "scan_status": "pending",
            "error": "",
        }
    )
    return database, digest


def install_fakes(monkeypatch, output, *, return_code=0, help_text=HELP_TEXT):
    import subprocess

    calls = []
    process = FakeProcess(return_code)

    def fake_run(command, **kwargs):
        calls.append(("help", command))
        return type(
            "Result",
            (),
            {"returncode": 0 if help_text else 1, "stdout": help_text, "stderr": ""},
        )()

    def fake_popen(command, **kwargs):
        calls.append(("scan", command))
        assert kwargs["stdout"] is not None
        assert kwargs["stdout"] is not subprocess.PIPE
        assert kwargs["stderr"] is not None
        kwargs["stdout"].write(output)
        kwargs["stdout"].flush()
        return process

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls, process


def test_scanner_disables_verification_and_persists_only_sanitized_fields(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    line = json.dumps(result_json()).encode() + b"\n"
    calls, _ = install_fakes(monkeypatch, line)
    scanner = TruffleHogScanner(
        database,
        workspace=tmp_path,
        executable="trufflehog",
        logger=logging.getLogger("test-trufflehog"),
    )

    summary = scanner.run()

    assert summary.scanned == 1
    assert summary.findings == 1
    assert summary.failed == 0
    command = next(entry[1] for entry in calls if entry[0] == "scan")
    assert command[0:2] == ["trufflehog", "filesystem"]
    assert "--no-verification" in command
    assert "--no-update" in command
    assert "--json" in command
    assert "--concurrency=1" in command
    assert "--fail-on-scan-errors" in command
    assert command[-2].endswith("/jadx")
    assert command[-1].endswith("/apktool")

    output = tmp_path / "results/org.example.app/7/trufflehog/findings.json"
    sanitized = output.read_text(encoding="utf-8")
    assert RAW_SECRET not in sanitized
    assert "secret-part" not in sanitized
    assert "do-not-store" not in sanitized
    records = json.loads(sanitized)
    assert records[0]["detector_name"] == "AWS"
    assert records[0]["file_path"].endswith("Config.java")
    assert records[0]["line"] == 23
    assert records[0]["verification"] == "disabled"
    assert len(records[0]["fingerprint"]) == 64
    assert RAW_SECRET not in (tmp_path / "reports/findings.csv").read_text(encoding="utf-8")
    assert database.read_processing_status()[digest]["scan_status"] == "success"


def test_scanner_refuses_to_run_when_no_verification_flag_is_unavailable(monkeypatch, tmp_path):
    database, _ = make_workspace(tmp_path)
    calls, _ = install_fakes(monkeypatch, b"", help_text="filesystem help --json --concurrency")

    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")
    summary = scanner.run()

    assert summary.failed == 1
    assert [entry[0] for entry in calls] == ["help"]
    assert not (tmp_path / "results/org.example.app/7/trufflehog/findings.json").exists()


def test_malformed_json_prevents_results_from_being_published(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    prior = tmp_path / "results/org.example.app/7/trufflehog/findings.json"
    prior.parent.mkdir(parents=True, exist_ok=True)
    prior.write_text(json.dumps([{"detector_name": "STALE"}]), encoding="utf-8")
    _calls, _ = install_fakes(monkeypatch, b"{not-json}\n")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.failed == 1
    assert summary.scanned == 0
    assert not (tmp_path / "results/org.example.app/7/trufflehog/findings.json").exists()
    assert database.read_processing_status()[digest]["scan_status"] == "failed"
    with (tmp_path / "reports/findings.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []


def test_existing_success_is_skipped_unless_forced(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "scan_status": "success",
        }
    )
    calls, _ = install_fakes(monkeypatch, b"")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.scanned == 0
    assert summary.skipped == 1
    assert calls == []


def test_aggregate_csv_is_sanitized_and_has_expected_columns(monkeypatch, tmp_path):
    database, _ = make_workspace(tmp_path)
    line = json.dumps(result_json()).encode() + b"\n"
    install_fakes(monkeypatch, line)
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")
    scanner.run()

    with (tmp_path / "reports/findings.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["package_id"] == "org.example.app"
    assert rows[0]["detector_name"] == "AWS"
    assert rows[0]["verification"] == "disabled"
    assert RAW_SECRET not in str(rows)



def test_scanner_kills_process_when_timeout_expires(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    calls, process = install_fakes(monkeypatch, b"")
    scanner = TruffleHogScanner(
        database,
        workspace=tmp_path,
        executable="trufflehog",
        timeout_seconds=1,
    )

    def wait_with_timeout(timeout=None):
        if not process.killed:
            raise subprocess.TimeoutExpired("trufflehog", timeout)
        return -9

    process.wait = wait_with_timeout
    summary = scanner.run()

    assert summary.failed == 1
    assert process.killed
    assert database.read_processing_status()[digest]["scan_status"] == "failed"
    assert [entry[0] for entry in calls] == ["help", "scan"]


def test_scanner_rejects_aggregate_json_output_over_configured_limit(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    output = json.dumps(result_json()).encode() + b"\\n"
    install_fakes(monkeypatch, output)
    scanner = TruffleHogScanner(
        database,
        workspace=tmp_path,
        executable="trufflehog",
        max_output_bytes=10,
    )

    summary = scanner.run()

    assert summary.failed == 1
    assert summary.scanned == 0
    assert database.read_processing_status()[digest]["scan_status"] == "failed"
    assert not (tmp_path / "results/org.example.app/7/trufflehog/findings.json").exists()
