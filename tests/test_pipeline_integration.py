"""End-to-end local pipeline test using real subprocesses and synthetic tool fixtures."""
from __future__ import annotations

import hashlib
import json
import textwrap
from pathlib import Path

import pytest

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.apk_surface import (
    refresh_secret_links,
    run_static_surface_analysis,
)
from apkworkbench.analysis.trufflehog import TruffleHogScanner
from apkworkbench.cli.main import (
    _trufflehog_stage_outcome,
    _write_bundle_stage_statuses,
    _write_run_stage_statuses,
)
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.reporting.generator import ReportGenerator


def write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_trufflehog_success_requires_complete_counted_outputs(tmp_path):
    bundle = tmp_path / "bundle"
    output = bundle / "trufflehog"
    output.mkdir(parents=True)

    status, counts, diagnostic = _trufflehog_stage_outcome(
        bundle, {"scan_status": "success"}
    )
    assert status == "partial"
    assert counts == {"total_seen": 0, "verified": 0, "unverified": 0}
    assert "summary or complete split outputs" in diagnostic

    (output / "scan.json").write_text(
        json.dumps({"total_seen": 1, "verified": 1, "unverified": 0}),
        encoding="utf-8",
    )
    (output / "findings.json").write_text(
        json.dumps([{"Verified": True}]), encoding="utf-8"
    )
    (output / "findings-verified.json").write_text(
        json.dumps([{"Verified": True}]), encoding="utf-8"
    )
    (output / "findings-unverified.json").write_text("[]", encoding="utf-8")
    status, counts, diagnostic = _trufflehog_stage_outcome(
        bundle, {"scan_status": "success"}
    )
    assert status == "success"
    assert counts == {"total_seen": 1, "verified": 1, "unverified": 0}
    assert diagnostic == ""


def test_refresh_secret_links_rejects_non_object_surface_and_coverage(tmp_path):
    digest = hashlib.sha256(b"invalid surface schema").hexdigest()
    run_id = "invalid-surface-schema"
    row = {
        "run_id": run_id,
        "package_id": "com.example.app",
        "version_code": "1",
        "sha256": digest,
        "source": "google_play",
    }

    class FakeDatabase:
        def read_download_history(self):
            return [row]

        def read_manifest(self, selected_run_id):
            assert selected_run_id == run_id
            return [row]

        def read_processing_status(self):
            return {}

    surface_dir = (
        tmp_path / "results/com.example.app/1" / digest / "surface"
    )
    surface_dir.mkdir(parents=True)
    static_path = surface_dir / "static-analysis.json"

    static_path.write_text("[]", encoding="utf-8")
    with pytest.raises(TypeError, match="Surface result must be a JSON object"):
        refresh_secret_links(FakeDatabase(), tmp_path, run_id=run_id)

    static_path.write_text('{"coverage": []}', encoding="utf-8")
    with pytest.raises(TypeError, match="Surface coverage must be a JSON object"):
        refresh_secret_links(FakeDatabase(), tmp_path, run_id=run_id)


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
                ".class public Lcom/example/Main;\\n"
                ".super Ljava/lang/Object;\\n"
                ".method public onCreate()V\\n"
                "    .locals 0\\n"
                "    return-void\\n"
                ".end method\\n",
                encoding="utf-8",
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
                        "file": "smali/com/example/Main.smali", "line": 4
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

    bundle_dir = workspace / "results/org.example.integration/1" / digest
    embedded_dex_path = bundle_dir / "apktool/assets/embedded/classes.dex"
    embedded_dex_path.parent.mkdir(parents=True, exist_ok=True)
    embedded_dex_path.write_bytes(b"dex\n035\x00")
    embedded_dex_result = {
        "status": "success",
        "metrics": {
            "dex_files": 1,
            "classes": 1,
            "internal_methods": 1,
            "class_model_count": 1,
            "method_model_count": 1,
        },
        "coverage": {"dex_parsing": "success", "code_model": "success"},
        "class_model": [{
            "class_name": "Lcom/example/Embedded;",
            "dex_index": 0,
            "dex_source": "assets/embedded/classes.dex",
        }],
        "method_model": [{
            "full_name": "Lcom/example/Embedded; read ()V",
            "class_name": "Lcom/example/Embedded;",
            "dex_index": 0,
            "method_name": "read",
            "descriptor": "()V",
            "dex_source": "assets/embedded/classes.dex",
        }],
        "external_method_references": [],
        "internal_call_graph": [{
            "caller": "Lcom/example/Embedded; read ()V",
            "callee": "Lcom/example/Embedded; helper ()V",
            "dex_class": 0,
        }],
        "dex_api_strings": [],
        "reflection_sites": [],
        "permission_api_usage": [],
        "string_class_index": {},
        "diagnostics": [],
        "limitations": [],
    }
    monkeypatch.setattr(
        apk_surface,
        "_analyze_dex_payloads",
        lambda _payloads, *, target_sdk: embedded_dex_result,
    )
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
                "method_name": "onCreate",
                "descriptor": "()V",
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
    dex_analysis = static_payload["dex_analysis"]
    assert dex_analysis["metrics"]["external_methods_referenced"] == 3
    assert dex_analysis["metrics"]["dex_files"] == 2
    classes = {item["class_name"]: item for item in dex_analysis["class_model"]}
    assert "Lcom/example/Embedded;" in classes
    assert classes["Lcom/example/Embedded;"]["dex_index"] == 1
    assert classes["Lcom/example/Embedded;"]["dex_source"] == (
        "assets/embedded/classes.dex"
    )
    assert dex_analysis["internal_call_graph"][-1]["dex_class"] == 1

    reused_surface = run_static_surface_analysis(
        database, workspace, run_id=run_id
    )
    assert reused_surface["skipped"] == 1
    assert reused_surface["artifacts"][0]["status"] == "skipped_reused"
    marker = json.loads(
        (
            workspace / "results/runs" / run_id / "static-analysis-run.json"
        ).read_text(encoding="utf-8")
    )
    assert marker["status"] == "success"

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
    assert secret_edges[0]["citations"][0]["evidence_kind"] == "smali_method"
    assert secret_edges[0]["citations"][0]["line_start"] == 3
    usage = static_payload["secret_usage"]
    assert usage["status"] == "partial"
    assert usage["mapped_count"] == 1
    assert usage["usage_unverified_count"] == 1
    assert usage["findings"][0]["usage_status"] == "mapped"
    assert usage["findings"][1]["usage_status"] == "usage_unverified"
    assert usage["findings"][1]["reason"] == "class_not_in_dex_model"
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
    assert empty_payload["coverage"]["link_type_method_secret"] == "not_applicable"
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

    status_result = _write_bundle_stage_statuses(database, workspace, run_id)
    assert status_result == {
        "bundles": 1,
        "statuses_written": 5,
        "frozen_skipped": 0,
        "missing": 0,
    }

    # Freeze the artifact bundle: handoff.json + hashes.sha256 + read-only
    # evidence so verify-workspace can prove it was not tampered with.
    bundle_dir = workspace / "results/org.example.integration/1" / digest
    database.freeze_evidence(bundle_dir)
    assert (bundle_dir / "handoff.json").is_file()
    assert (bundle_dir / "hashes.sha256").is_file()
    hashes = (bundle_dir / "hashes.sha256").read_text(encoding="utf-8")
    assert "surface/static-analysis.json" in hashes
    assert "trufflehog/findings.json" in hashes
    assert "stages/surface/status.json" in hashes
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
    _write_run_stage_statuses(
        database,
        workspace,
        run_id,
        reconciliation=reconciliation,
        frozen=1,
        pipeline_issues=["report"],
    )
    run_status = json.loads(
        (
            workspace / "results/runs" / run_id / "stages/pipeline/status.json"
        ).read_text(encoding="utf-8")
    )
    run_stage_dirs = {
        path.parent.name
        for path in (workspace / "results/runs" / run_id / "stages").glob(
            "*/status.json"
        )
    }
    assert run_stage_dirs == {
        "discover",
        "download",
        "verification",
        "decompile",
        "surface",
        "trufflehog",
        "report",
        "reconciliation",
        "freeze",
        "pipeline",
    }
    assert run_status["status"] == "partial"
    assert run_status["diagnostics"][0]["message"].startswith(
        "report; Stages not fully successful:"
    )
    frozen_linkage = refresh_secret_links(database, workspace, run_id=run_id)
    assert frozen_linkage["frozen"] == 1
    assert database.verify_workspace(bundle_dir)["status"] == "ok"
