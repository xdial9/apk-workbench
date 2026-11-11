"""End-to-end local pipeline test using real subprocesses and synthetic tool fixtures."""
from __future__ import annotations

import hashlib
import textwrap
from pathlib import Path

from apkworkbench.analysis.apk_surface import run_static_surface_analysis
from apkworkbench.analysis.trufflehog import TruffleHogScanner
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.reporting.generator import ReportGenerator


def write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_real_subprocess_pipeline_completes_and_reconciles_one_artifact(tmp_path):
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()

    apk_bytes = b"synthetic verified APK fixture for integration testing"
    digest = hashlib.sha256(apk_bytes).hexdigest()
    apk_path = (
        workspace / "downloads/org.example.integration/1" / digest / "app.apk"
    )
    apk_path.parent.mkdir(parents=True)
    apk_path.write_bytes(apk_bytes)

    run_id = "integration-run"
    manifest_row = {
        "run_id": run_id,
        "selection_order": 1,
        "selected_at": "2026-11-07T12:00:00+00:00",
        "package_id": "org.example.integration",
        "app_name": "Integration Fixture",
        "version_code": 1,
        "version_name": "1.0",
        "source": "google_play",
        "download_url": "google-play://org.example.integration/1/base.apk",
        "sha256": digest,
        "size": len(apk_bytes),
        "signer_sha256": "",
        "local_path": str(apk_path),
        "index_sha256": "a" * 64,
    }
    database.write_manifest(run_id, [manifest_row])
    database.append_history(
        {
            **manifest_row,
            "downloaded_at": "2026-11-07T12:00:00+00:00",
        }
    )

    apktool = write_executable(
        tmp_path / "apktool-fixture",
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import pathlib
            import sys

            args = sys.argv[1:]
            output = pathlib.Path(args[args.index("-o") + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / "AndroidManifest.xml").write_text("<manifest />", encoding="utf-8")
            print("Apktool integration fixture completed")
            """,
        ),
    )
    trufflehog = write_executable(
        tmp_path / "trufflehog-fixture",
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import sys

            if len(sys.argv) > 2 and sys.argv[2] == "--help":
                print(
                    "filesystem --results=RESULTS --no-update --json "
                    "--concurrency --fail-on-scan-errors"
                )
                raise SystemExit(0)

            finding = {
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "res/AndroidManifest.xml", "line": 1}}
                },
                "DetectorType": 2,
                "DetectorName": "SYNTHETIC_TEST",
                "DecoderName": "PLAIN",
                "Verified": True,
                "Raw": "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED",
                "RawV2": "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED",
                "ExtraData": {"secret": "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED"},
            }
            print(json.dumps(finding))
            """,
        ),
    )

    decompilation = DecompilationRunner(
        database,
        workspace=workspace,
        apktool_executable=str(apktool),
        timeout_seconds=20,
    ).run(run_id=run_id)
    assert decompilation.examined == 1
    assert decompilation.completed == 1
    assert decompilation.failed == 0
    assert database.read_processing_status()[digest]["jadx_status"] == "not_used"

    surface = run_static_surface_analysis(database, workspace, run_id=run_id)
    assert surface["completed"] == 1
    assert surface["failed"] == 0
    assert (workspace / "results/org.example.integration/1" / digest / "static-analysis.json").is_file()

    analysis = TruffleHogScanner(
        database,
        workspace=workspace,
        executable=str(trufflehog),
        timeout_seconds=20,
    ).run(run_id=run_id)
    assert analysis.scanned == 1
    assert analysis.findings == 1
    assert analysis.failed == 0
    assert analysis.finding_records[0]["finding"]["Raw"] == "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED"

    reports = ReportGenerator(database, workspace=workspace).run()
    assert reports.generated == 1
    assert reports.with_findings == 1
    assert reports.total_findings == 1

    report_path = (
        workspace / "reports/org.example.integration/1" / digest / "report.json"
    )
    report_text = report_path.read_text(encoding="utf-8")
    assert "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED" in report_text
    assert "SYNTHETIC_TEST" in report_text
    html_path = report_path.with_name("report.html")
    html_text = html_path.read_text(encoding="utf-8")
    assert "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED" in html_text
    assert "Complete original JSON" in html_text

    reconciliation = database.reconcile_run(run_id)
    assert reconciliation["total"] == 1
    assert reconciliation["complete"] == 1
    assert reconciliation["counts"] == {"complete": 1}
