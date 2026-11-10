"""Tests for complete TruffleHog result retention and safe execution."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import subprocess
import pytest
import shutil
from pathlib import Path

from apkworkbench.analysis.trufflehog import AnalysisError, TruffleHogScanner
from apkworkbench.database.workspace import WorkspaceDatabase


RAW_SECRET = "AKIAIOSFODNN7EXAMPLE"
HELP_TEXT = (
    "filesystem command help --results=RESULTS --no-update --json "
    "--concurrency --fail-on-scan-errors"
)


class FakeProcess:
    def __init__(self, stdout, return_code: int = 0):
        self.stdout = stdout
        self.return_code = return_code
        self.killed = False
        self.pid = 424242

    def wait(self, timeout=None):
        return self.return_code

    def kill(self):
        self.killed = True


def result_json(raw=RAW_SECRET):
    return {
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "/workspace/results/org.example.app/7/apktool/res/values/config.xml",
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
        "Verified": True,
        "Raw": raw,
        "RawV2": "secret-part",
        "Redacted": "AKIA...EXAMPLE",
        "ExtraData": {"account": "123456789012", "sensitive": "do-not-store"},
    }


def make_workspace(tmp_path: Path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    digest = hashlib.sha256(b"downloaded apk").hexdigest()
    apk = tmp_path / "downloads/org.example.app/7" / digest / "app.apk"
    apk.parent.mkdir(parents=True, exist_ok=True)
    apk.write_bytes(b"downloaded apk")
    database.append_history(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": 7,
            "version_name": "7.0",
            "source": "google_play",
            "download_url": "google-play://fixture/app.apk",
            "local_path": str(apk),
            "size": len(b"downloaded apk"),
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    for tool in ("apktool",):
        directory = tmp_path / "results/org.example.app/7" / digest / tool
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


def install_fakes(monkeypatch, output, *, return_code=0, help_text=HELP_TEXT, stderr=b""):
    import subprocess

    calls = []
    read_fd, write_fd = os.pipe()
    if output:
        os.write(write_fd, output)
    os.close(write_fd)
    process = FakeProcess(os.fdopen(read_fd, "rb", buffering=0), return_code)

    def fake_run(command, **kwargs):
        calls.append(("help", command))
        return type(
            "Result",
            (),
            {"returncode": 0 if help_text else 1, "stdout": help_text, "stderr": ""},
        )()

    def fake_popen(command, **kwargs):
        calls.append(("scan", command))
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is not subprocess.DEVNULL
        assert kwargs["bufsize"] == 0
        assert kwargs["start_new_session"] is True
        kwargs["stderr"].write(stderr)
        return process

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls, process


def test_scanner_processes_saved_partial_apktool_output(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    database.update_processing_status({
        "sha256": digest,
        "package_id": "org.example.app",
        "version_code": "7",
        "apktool_status": "partial",
    })
    calls, _ = install_fakes(monkeypatch, (json.dumps(result_json()) + "\n").encode())
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.scanned == 1
    assert summary.failed == 0
    assert database.read_processing_status()[digest]["apktool_status"] == "partial"
    assert any(entry[0] == "scan" for entry in calls)


def test_scanner_selects_verified_results_and_persists_complete_original_objects(monkeypatch, tmp_path):
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
    assert summary.finding_records == ({
        "package_id": "org.example.app",
        "version_code": "7",
        "sha256": digest,
        "finding": result_json(),
    },)
    command = next(entry[1] for entry in calls if entry[0] == "scan")
    assert command[0:2] == ["trufflehog", "filesystem"]
    assert "--results=verified" in command
    assert "--no-update" in command
    assert "--json" in command
    assert "--concurrency=1" in command
    assert "--fail-on-scan-errors" in command
    assert command[-1].endswith("/apktool")
    assert not any(arg.endswith("/jadx") for arg in command)

    output = tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json"
    records = json.loads(output.read_text(encoding="utf-8"))
    assert records == [result_json()]
    assert records[0]["Raw"] == RAW_SECRET
    assert records[0]["RawV2"] == "secret-part"
    assert records[0]["ExtraData"]["sensitive"] == "do-not-store"
    assert json.loads((output.parent / "findings-verified.json").read_text(encoding="utf-8")) == records
    assert RAW_SECRET in (output.parent / "stdout.jsonl").read_text(encoding="utf-8")
    assert (output.parent / "stderr.log").is_file()
    assert "CREDENTIAL VERIFICATION: ENABLED" in (output.parent / "trufflehog.log").read_text(encoding="utf-8")
    aggregate = (tmp_path / "reports/findings.csv").read_text(encoding="utf-8")
    assert RAW_SECRET in aggregate
    assert "finding_json" in aggregate
    assert database.read_processing_status()[digest]["scan_status"] == "success"



def test_scanner_rejects_unverified_findings(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    finding = result_json()
    finding["Verified"] = False
    install_fakes(monkeypatch, (json.dumps(finding) + "\n").encode())
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.failed == 1
    assert summary.scanned == 0
    assert not (tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json").exists()
    assert database.read_processing_status()[digest]["scan_status"] == "failed"


def test_scanner_preserves_repeated_original_objects_without_deduplication(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    original = result_json()
    line = (json.dumps(original) + "\n" + json.dumps(original) + "\n").encode()
    install_fakes(monkeypatch, line)
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    output = tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json"
    assert json.loads(output.read_text(encoding="utf-8")) == [original, original]
    assert summary.findings == 2
    assert len(summary.finding_records) == 2



def test_scanner_refuses_to_run_when_results_flag_is_unavailable(monkeypatch, tmp_path):
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
    assert prior.is_file()
    assert "STALE" in prior.read_text(encoding="utf-8")
    assert database.read_processing_status()[digest]["scan_status"] == "failed"
    with (tmp_path / "reports/findings.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []


def test_existing_success_is_skipped_unless_forced(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    output = tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("[]", encoding="utf-8")
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


def test_successful_scan_is_retried_when_findings_output_is_missing(monkeypatch, tmp_path):
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

    assert summary.scanned == 1
    assert summary.failed == 0
    assert [entry[0] for entry in calls] == ["help", "scan"]
    output = tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json"
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8")) == []


def test_successful_scan_is_retried_when_findings_output_is_invalid(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    output = tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("{not-json}", encoding="utf-8")
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

    assert summary.scanned == 1
    assert summary.failed == 0
    assert [entry[0] for entry in calls] == ["help", "scan"]
    assert json.loads(output.read_text(encoding="utf-8")) == []


def test_aggregate_csv_contains_complete_original_finding_json(monkeypatch, tmp_path):
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
    assert rows[0]["verification"] == "verified"
    assert json.loads(rows[0]["finding_json"]) == result_json()
    assert RAW_SECRET in rows[0]["finding_json"]



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
    monkeypatch.setattr(
        os, "killpg", lambda _pid, _sig: setattr(process, "killed", True)
    )
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


def test_scanner_rejects_results_root_symlink_escape(tmp_path):
    database, _digest = make_workspace(tmp_path)
    results = tmp_path / "results"
    for child in results.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    results.rmdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-results"
    outside.mkdir()
    results.symlink_to(outside, target_is_directory=True)

    scanner = TruffleHogScanner(database, workspace=tmp_path)
    with pytest.raises(AnalysisError, match="Results directory resolves outside"):
        scanner.run()



def test_scanner_accepts_kong_style_results_flag_syntax(monkeypatch, tmp_path):
    database, _digest = make_workspace(tmp_path)
    calls, _process = install_fakes(
        monkeypatch,
        b"",
        help_text=(
            "filesystem --results=RESULTS --[no-]no-update "
            "--[no-]json --concurrency=N --[no-]fail-on-scan-errors"
        ),
    )
    scanner = TruffleHogScanner(database, workspace=tmp_path)

    summary = scanner.run()

    assert summary.scanned == 1
    assert summary.failed == 0
    assert [entry[0] for entry in calls] == ["help", "scan"]



def test_scanner_only_processes_artifacts_listed_in_the_selected_run_manifest(monkeypatch, tmp_path):
    database, selected_digest = make_workspace(tmp_path)
    selected_history = next(
        row for row in database.read_download_history() if row["sha256"] == selected_digest
    )
    database.write_manifest(
        "test-run",
        [
            {
                "run_id": "test-run",
                "selection_order": 1,
                "selected_at": "2026-11-07T12:00:00+00:00",
                "package_id": selected_history["package_id"],
                "app_name": "Example",
                "version_code": selected_history["version_code"],
                "version_name": selected_history["version_name"],
                "source": "google_play",
                "download_url": selected_history["download_url"],
                "sha256": selected_digest,
                "size": selected_history["size"],
                "signer_sha256": "",
                "local_path": selected_history["local_path"],
                "index_sha256": "f" * 64,
            }
        ],
    )

    old_digest = hashlib.sha256(b"older downloaded apk").hexdigest()
    old_apk = tmp_path / "downloads/org.example.old/2" / old_digest / "app.apk"
    old_apk.parent.mkdir(parents=True, exist_ok=True)
    old_apk.write_bytes(b"older downloaded apk")
    database.append_history(
        {
            "sha256": old_digest,
            "package_id": "org.example.old",
            "version_code": 2,
            "version_name": "2.0",
            "source": "google_play",
            "download_url": "google-play://fixture/old.apk",
            "local_path": str(old_apk),
            "size": old_apk.stat().st_size,
            "run_id": "old-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    for tool in ("apktool",):
        output = tmp_path / "results/org.example.old/2" / old_digest / tool
        output.mkdir(parents=True)
        (output / "placeholder.txt").write_text("older source", encoding="utf-8")
    database.update_processing_status(
        {
            "sha256": old_digest,
            "package_id": "org.example.old",
            "version_code": "2",
            "jadx_status": "success",
            "apktool_status": "success",
            "scan_status": "pending",
            "error": "",
        }
    )
    database.write_manifest(
        "old-run",
        [
            {
                "run_id": "old-run",
                "selection_order": 1,
                "selected_at": "2026-11-07T12:00:00+00:00",
                "package_id": "org.example.old",
                "app_name": "Old",
                "version_code": 2,
                "version_name": "2.0",
                "source": "google_play",
                "download_url": "google-play://fixture/old.apk",
                "sha256": old_digest,
                "size": old_apk.stat().st_size,
                "signer_sha256": "",
                "local_path": str(old_apk),
                "index_sha256": "f" * 64,
            }
        ],
    )

    calls, _ = install_fakes(monkeypatch, b"")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")
    summary = scanner.run(run_id="test-run")

    assert summary.scanned == 1
    assert summary.failed == 0
    assert summary.skipped == 0
    scan_commands = [entry[1] for entry in calls if entry[0] == "scan"]
    assert len(scan_commands) == 1
    assert all("org.example.old" not in arg for arg in scan_commands[0])
    assert database.read_processing_status()[old_digest]["scan_status"] == "pending"


def test_scanner_refuses_empty_decompilation_directories(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    base = tmp_path / "results/org.example.app/7" / digest
    for tool in ("apktool",):
        shutil.rmtree(base / tool)
        (base / tool).mkdir()
    calls, _ = install_fakes(monkeypatch, b"")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.failed == 1
    assert summary.scanned == 0
    assert [entry[0] for entry in calls] == ["help"]
    assert "no usable files" in database.read_processing_status()[digest]["error"]


def test_scanner_rejects_symlinks_inside_decompilation_output(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    apktool = tmp_path / "results/org.example.app/7" / digest / "apktool"
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("not part of the decompilation", encoding="utf-8")
    (apktool / "outside.txt").symlink_to(outside)
    calls, _ = install_fakes(monkeypatch, b"")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.failed == 1
    assert summary.scanned == 0
    assert [entry[0] for entry in calls] == ["help"]
    assert "symlink" in database.read_processing_status()[digest]["error"]


def test_scanner_preserves_stderr_diagnostics_on_nonzero_exit(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    install_fakes(monkeypatch, b"", return_code=9, stderr=b"filesystem scan failed: permission denied")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.failed == 1
    assert "permission denied" in database.read_processing_status()[digest]["error"]


def test_scanner_rejects_symlinked_parent_of_decompilation_directories(monkeypatch, tmp_path):
    database, _digest = make_workspace(tmp_path)
    results = tmp_path / "results"
    package_root = results / "org.example.app"
    real_package = results / "real-package"
    package_root.rename(real_package)
    package_root.symlink_to(real_package, target_is_directory=True)
    calls, _ = install_fakes(monkeypatch, b"")
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.failed == 1
    assert summary.scanned == 0
    assert [entry[0] for entry in calls] == ["help"]
    assert "symlinked decompilation path component" in database.read_processing_status()[
        _digest
    ]["error"]


def test_scanner_ignores_legacy_jadx_status_when_apktool_output_is_usable(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "jadx_status": "failed",
            "apktool_status": "success",
            "scan_status": "pending",
            "error": "Legacy JADX failure does not block Apktool analysis.",
        }
    )
    line = json.dumps(result_json()).encode() + b"\n"
    calls, _ = install_fakes(monkeypatch, line)
    scanner = TruffleHogScanner(database, workspace=tmp_path, executable="trufflehog")

    summary = scanner.run()

    assert summary.scanned == 1
    assert summary.failed == 0
    assert [entry[0] for entry in calls] == ["help", "scan"]
    assert database.read_processing_status()[digest]["scan_status"] == "success"
