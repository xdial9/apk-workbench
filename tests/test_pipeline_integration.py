"""End-to-end local pipeline test using real subprocesses and synthetic tool fixtures."""
from __future__ import annotations

import hashlib
import json
import textwrap
from pathlib import Path

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.apk_surface import (
    refresh_secret_links,
    run_static_surface_analysis,
)
from apkworkbench.analysis.trufflehog import TruffleHogScanner
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.reporting.generator import ReportGenerator


def write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_real_subprocess_pipeline_completes_and_reconciles_one_artifact(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()

    # A real (minimal) APK zip: the pipeline now inventories the archive
    # members of every artifact, so the fixture is a genuine zip file.
    import io
    import zipfile as _zipfile

    apk_stream = io.BytesIO()
    with _zipfile.ZipFile(apk_stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", b"dex\n000037\x00synthetic")
    apk_bytes = apk_stream.getvalue()
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
            (output / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example"><application><activity '
                'android:name="com.example.Main" android:exported="true" />'
                '</application></manifest>',
                encoding="utf-8",
            )
            smali = output / "smali/com/example"
            smali.mkdir(parents=True)
            (smali / "Main.smali").write_text(
                ".class public Lcom/example/Main;\\n", encoding="utf-8"
            )
            (smali / "Unmapped.smali").write_text(
                ".class public Lcom/example/Unmapped;\\n", encoding="utf-8"
            )
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
                    "Data": {"Filesystem": {
                        "file": "smali/com/example/Main.smali", "line": 1
                    }}
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
            finding["SourceMetadata"]["Data"]["Filesystem"]["file"] = (
                "smali/com/example/Unmapped.smali"
            )
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

    monkeypatch.setattr(
        apk_surface,
        "analyze_apk_dex",
        lambda _path, **_kwargs: {
            "status": "success",
            "analyzer": {"id": "androguard-dex", "version": "4.1.4"},
            "metrics": {"dex_files": 1, "external_methods_referenced": 3},
            "coverage": {"dex_parsing": "success"},
            "class_model": [{
                "class_name": "Lcom/example/Main;",
                "dex_index": 0,
                "source_file": "Main.java",
            }],
            "method_model": [{
                "full_name": "Lcom/example/Main; onCreate ()V",
                "class_name": "Lcom/example/Main;",
                "dex_index": 0,
            }],
            "external_method_references": [{
                "full_name": "Lokhttp3/Call; execute ()",
                "category": "network",
                "call_sites": [{"caller": "Lcom/example/Main; run ()V", "offset": 12}],
            }],
            "internal_call_graph": [],
            "dex_api_strings": [],
            "permission_api_usage": [],
            "diagnostics": [],
            "limitations": [],
        },
    )
    surface = run_static_surface_analysis(database, workspace, run_id=run_id)
    assert surface["completed"] == 1
    assert surface["failed"] == 0
    static_path = workspace / "results/org.example.integration/1" / digest / "surface" / "static-analysis.json"
    assert static_path.is_file()
    static_payload = __import__("json").loads(static_path.read_text(encoding="utf-8"))
    assert static_payload["dex_analysis"]["metrics"]["external_methods_referenced"] == 3

    analysis = TruffleHogScanner(
        database,
        workspace=workspace,
        executable=str(trufflehog),
        timeout_seconds=20,
    ).run(run_id=run_id)
    assert analysis.scanned == 1
    assert analysis.findings == 2
    assert analysis.failed == 0
    assert analysis.finding_records[0]["finding"]["Raw"] == "SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED"

    linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert linkage == {
        "updated": 1, "missing_surface": 0, "failed": 0, "frozen": 0
    }
    static_payload = json.loads(static_path.read_text(encoding="utf-8"))
    assert static_payload["secret_linkage"] == {
        "status": "success",
        "finding_count": 2,
    }
    link_path = workspace / "results/org.example.integration/1" / digest / "links.jsonl"
    links = [json.loads(line) for line in link_path.read_text().splitlines()]
    secret_edges = [
        edge for edge in links if edge["edge_type"] == "method->secret"
    ]
    assert len(secret_edges) == 1
    assert secret_edges[0]["from"] == "method:Lcom/example/Main; onCreate ()V"
    assert secret_edges[0]["citations"][1]["source_path"] == (
        "apktool/smali/com/example/Main.smali"
    )
    assert all(
        edge["citations"][1]["source_path"]
        != "apktool/smali/com/example/Unmapped.smali"
        for edge in secret_edges
    )
    chains_path = link_path.with_name("trace_chains.jsonl")
    chains = [json.loads(line) for line in chains_path.read_text().splitlines()]
    assert chains
    assert chains[0]["start_node"] == "component:activity:com.example.Main"
    assert chains[0]["end_node"] == secret_edges[0]["to"]

    findings_path = link_path.parent / "trufflehog/findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    findings_path.write_text("[]\n", encoding="utf-8")
    refresh_secret_links(database, workspace, run_id=run_id)
    empty_payload = json.loads(static_path.read_text(encoding="utf-8"))
    assert empty_payload["secret_linkage"] == {
        "status": "success",
        "finding_count": 0,
    }
    assert empty_payload["coverage"]["link_type_method_secret"] == "success"
    assert not [
        json.loads(line) for line in link_path.read_text().splitlines()
        if json.loads(line)["edge_type"] == "method->secret"
    ]

    findings_path.write_text(json.dumps(findings) + "\n", encoding="utf-8")
    database.update_processing_status({
        "sha256": digest,
        "scan_status": "",
        "error": "",
    })
    not_run_linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert not_run_linkage["failed"] == 0
    not_run_payload = json.loads(static_path.read_text(encoding="utf-8"))
    assert not_run_payload["secret_linkage"]["status"] == "not_run"
    assert not_run_payload["secret_linkage"]["finding_count"] is None
    assert not [
        json.loads(line) for line in link_path.read_text().splitlines()
        if json.loads(line)["edge_type"] == "method->secret"
    ]

    database.update_processing_status({
        "sha256": digest,
        "scan_status": "failed",
        "error": "synthetic scanner failure",
    })
    failed_linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert failed_linkage["failed"] == 1
    failed_payload = json.loads(static_path.read_text(encoding="utf-8"))
    assert failed_payload["secret_linkage"]["status"] == "failed"
    assert failed_payload["diagnostics"][-1]["code"] == (
        "trufflehog_secret_linkage_failed"
    )
    assert not [
        json.loads(line) for line in link_path.read_text().splitlines()
        if json.loads(line)["edge_type"] == "method->secret"
    ]

    database.update_processing_status({
        "sha256": digest,
        "scan_status": "success",
        "error": "",
    })
    findings_path.unlink()
    missing_linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert missing_linkage["failed"] == 1
    missing_payload = json.loads(static_path.read_text(encoding="utf-8"))
    assert missing_payload["secret_linkage"]["status"] == "failed"
    assert "Cannot use successful TruffleHog output" in (
        missing_payload["diagnostics"][-1]["message"]
    )
    findings_path.write_text(json.dumps(findings) + "\n", encoding="utf-8")
    refresh_secret_links(database, workspace, run_id=run_id)
    findings_path.write_text("{malformed\n", encoding="utf-8")
    malformed_linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert malformed_linkage["failed"] == 1
    malformed_payload = json.loads(static_path.read_text(encoding="utf-8"))
    assert malformed_payload["secret_linkage"]["status"] == "failed"
    findings_path.write_text(json.dumps(findings) + "\n", encoding="utf-8")
    refresh_secret_links(database, workspace, run_id=run_id)

    reports = ReportGenerator(database, workspace=workspace).run()
    assert reports.generated == 1
    assert reports.with_findings == 1
    assert reports.total_findings == 2

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

    # Freeze the artifact bundle: handoff.json + hashes.sha256 + read-only
    # evidence so verify-workspace can prove it was not tampered with.
    bundle_dir = workspace / "results/org.example.integration/1" / digest
    database.freeze_evidence(bundle_dir)
    assert (bundle_dir / "handoff.json").is_file()
    assert (bundle_dir / "hashes.sha256").is_file()
    hashes = (bundle_dir / "hashes.sha256").read_text(encoding="utf-8")
    assert "surface/static-analysis.json" in hashes
    assert "trufflehog/findings.json" in hashes
    assert "handoff.json" in hashes
    handoff = json.loads((bundle_dir / "handoff.json").read_text(encoding="utf-8"))
    assert handoff["schema_version"] == 1
    assert handoff["bundle_id"] == bundle_dir.name
    assert handoff["analyzer"]["id"] == "apk-surface"
    assert handoff["file_hashes"]["surface/static-analysis.json"]
    # verify-workspace should pass on the frozen bundle.
    verify = database.verify_workspace(bundle_dir)
    assert verify["status"] == "ok"
    assert verify["mismatches"] == []
    assert verify["missing"] == []
    assert verify["extra"] == []
    frozen_linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert frozen_linkage["frozen"] == 1
    assert database.verify_workspace(bundle_dir)["status"] == "ok"
