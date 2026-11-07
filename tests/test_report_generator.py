"""Tests for per-APK reports preserving complete original findings."""
from __future__ import annotations

import json
import pytest
import shutil
from pathlib import Path

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.reporting.generator import ReportGenerator, ReportingError


def setup_workspace(tmp_path: Path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    digest = "a" * 64
    database.append_history(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "app_name": "Example <App>",
            "version_code": 12,
            "version_name": "1.2",
            "source": "google_play",
            "download_url": "google-play://fixture/app.apk",
            "local_path": str(tmp_path / "downloads/org.example.app/12" / digest / "app.apk"),
            "size": 20,
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "b" * 64,
        }
    )
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "12",
            "jadx_status": "success",
            "apktool_status": "success",
            "scan_status": "success",
            "error": "",
        }
    )
    finding_path = tmp_path / "results/org.example.app/12" / digest / "trufflehog/findings.json"
    finding_path.parent.mkdir(parents=True)
    finding_path.write_text(
        json.dumps(
            [
                {
                    "DetectorName": "<script>alert(1)</script>",
                    "DetectorType": 7,
                    "DecoderName": "PLAIN",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "sources/Example.java", "line": 51}}},
                    "Raw": "MUST_NOT_APPEAR_IN_REPORTS",
                    "ExtraData": {"credential": "MUST_NOT_APPEAR_IN_REPORTS"},
                }
            ]
        ),
        encoding="utf-8",
    )
    return database


def test_generates_json_and_html_with_complete_original_findings(tmp_path):
    database = setup_workspace(tmp_path)
    summary = ReportGenerator(database, workspace=tmp_path).run()

    assert summary.generated == 1
    assert summary.with_findings == 1
    assert summary.total_findings == 1

    report_dir = tmp_path / "reports/org.example.app/12" / ("a" * 64)
    report_json = (report_dir / "report.json").read_text(encoding="utf-8")
    report_html = (report_dir / "report.html").read_text(encoding="utf-8")

    assert "MUST_NOT_APPEAR_IN_REPORTS" in report_json
    assert "MUST_NOT_APPEAR_IN_REPORTS" in report_html
    assert "<script>alert(1)</script>" not in report_html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report_html
    assert "Credential verification was disabled" in report_html
    assert "Complete original JSON" in report_html

    parsed = json.loads(report_json)
    assert parsed["artifact"]["app_name"] == "Example <App>"
    assert parsed["processing"]["jadx_status"] == "success"
    assert parsed["analysis"]["verification"] == "disabled"
    assert parsed["findings"][0]["Raw"] == "MUST_NOT_APPEAR_IN_REPORTS"
    assert parsed["findings"][0]["ExtraData"]["credential"] == "MUST_NOT_APPEAR_IN_REPORTS"


def test_report_refuses_missing_findings_file_after_successful_scan(tmp_path):
    database = setup_workspace(tmp_path)
    (tmp_path / "results/org.example.app/12" / ("a" * 64) / "trufflehog/findings.json").unlink()

    with pytest.raises(ReportingError, match="missing despite a successful scan"):
        ReportGenerator(database, workspace=tmp_path).run()



def test_previous_findings_are_hidden_when_latest_scan_failed(tmp_path):
    database = setup_workspace(tmp_path)
    database.update_processing_status(
        {
            "sha256": "a" * 64,
            "package_id": "org.example.app",
            "version_code": "12",
            "scan_status": "failed",
            "error": "TruffleHog failed",
        }
    )

    summary = ReportGenerator(database, workspace=tmp_path).run()

    assert summary.generated == 1
    assert summary.with_findings == 0
    parsed = json.loads(
        (tmp_path / "reports/org.example.app/12" / ("a" * 64) / "report.json").read_text(encoding="utf-8")
    )
    assert parsed["findings"] == []
    assert parsed["processing"]["scan_status"] == "failed"


def test_report_generator_rejects_results_root_symlink_escape(tmp_path):
    database = setup_workspace(tmp_path)
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

    with pytest.raises(ReportingError, match="results directory resolves outside"):
        ReportGenerator(database, workspace=tmp_path).run()


def test_report_generator_rejects_reports_root_symlink_escape(tmp_path):
    database = setup_workspace(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    reports.rmdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-reports"
    outside.mkdir()
    reports.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReportingError, match="reports directory resolves outside"):
        ReportGenerator(database, workspace=tmp_path).run()


def test_report_generator_rejects_symlinked_findings_file(tmp_path):
    database = setup_workspace(tmp_path)
    finding_path = (
        tmp_path / "results/org.example.app/12" / ("a" * 64)
        / "trufflehog/findings.json"
    )
    target = finding_path.with_name("other-findings.json")
    target.write_text("[]", encoding="utf-8")
    finding_path.unlink()
    finding_path.symlink_to(target)

    with pytest.raises(ReportingError, match="symlinked findings file"):
        ReportGenerator(database, workspace=tmp_path).run()


def test_report_generator_rejects_symlinked_package_output_parent(tmp_path):
    database = setup_workspace(tmp_path)
    reports = tmp_path / "reports"
    package_root = reports / "org.example.app"
    real_package = reports / "real-package"
    package_root.mkdir(parents=True)
    package_root.rename(real_package)
    package_root.symlink_to(real_package, target_is_directory=True)

    with pytest.raises(ReportingError, match="Report output path escapes or aliases"):
        ReportGenerator(database, workspace=tmp_path).run()
