"""Tests for run-manifest reconciliation and terminal artifact accounting."""
from __future__ import annotations

from apkworkbench.database.workspace import WorkspaceDatabase


RUN_ID = "reconcile-run"


def manifest_row(index: int) -> dict[str, object]:
    digest = f"{index:064x}"
    return {
        "run_id": RUN_ID,
        "selection_order": index,
        "selected_at": "2026-11-07T12:00:00+00:00",
        "package_id": f"org.example.app{index}",
        "app_name": f"Example {index}",
        "version_code": 1,
        "version_name": "1.0",
        "source": "google_play",
        "download_url": f"google-play://fixture/app{index}.apk",
        "sha256": digest,
        "size": 100,
        "signer_sha256": "",
        "local_path": f"/workspace/downloads/app{index}.apk",
        "index_sha256": "b" * 64,
    }


def add_history(database: WorkspaceDatabase, selected: dict[str, object]) -> None:
    database.append_history(
        {
            "sha256": selected["sha256"],
            "package_id": selected["package_id"],
            "app_name": selected["app_name"],
            "version_code": selected["version_code"],
            "version_name": selected["version_name"],
            "source": "google_play",
            "download_url": selected["download_url"],
            "local_path": selected["local_path"],
            "size": selected["size"],
            "run_id": RUN_ID,
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": selected["index_sha256"],
        }
    )


def add_attempt(
    database: WorkspaceDatabase, selected: dict[str, object], status: str, error: str = ""
) -> None:
    database.append_attempt(
        {
            "timestamp": "2026-11-07T12:00:00+00:00",
            "run_id": RUN_ID,
            "sha256": selected["sha256"],
            "package_id": selected["package_id"],
            "download_url": selected["download_url"],
            "status": status,
            "bytes_received": 0,
            "error": error,
        }
    )


def add_processing(
    database: WorkspaceDatabase,
    selected: dict[str, object],
    *,
    jadx: str = "not_used",
    apktool: str = "pending",
    scan: str = "pending",
    error: str = "",
) -> None:
    database.update_processing_status(
        {
            "sha256": selected["sha256"],
            "package_id": selected["package_id"],
            "version_code": "1",
            "jadx_status": jadx,
            "apktool_status": apktool,
            "scan_status": scan,
            "error": error,
        }
    )


def test_reconcile_run_accounts_for_every_manifest_entry(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    selected = [manifest_row(index) for index in range(1, 11)]
    database.write_manifest(RUN_ID, selected)

    # Complete artifact.
    add_history(database, selected[0])
    add_processing(database, selected[0], jadx="success", apktool="success", scan="success")
    findings = (
        tmp_path / "results" / selected[0]["package_id"] / "1"
        / selected[0]["sha256"] / "trufflehog" / "findings.json"
    )
    findings.parent.mkdir(parents=True, exist_ok=True)
    findings.write_text("[]", encoding="utf-8")

    # Failed and persistence-failed acquisitions.
    add_attempt(database, selected[1], "failed", "HTTP 503")
    add_attempt(database, selected[2], "persistence_failed", "history storage is read-only")

    # Acquired but not yet decompiled.
    add_history(database, selected[3])

    # Fully decompiled and awaiting scan.
    add_history(database, selected[4])
    add_processing(database, selected[4], jadx="success", apktool="success")

    # Decompilation failure.
    add_history(database, selected[5])
    add_processing(database, selected[5], apktool="failed", error="Apktool exit 9")

    # Interrupted or currently running stage.
    add_history(database, selected[6])
    add_processing(database, selected[6], apktool="running")

    # Analysis failure.
    add_history(database, selected[7])
    add_processing(
        database, selected[7], jadx="success", apktool="success", scan="failed",
        error="TruffleHog timeout",
    )

    # Acquisition interrupted before the artifact could be committed.
    add_attempt(database, selected[8], "interrupted", "SIGTERM received during stream")

    # No acquisition record or terminal attempt.
    result = database.reconcile_run(RUN_ID)

    assert result["total"] == 10
    assert result["complete"] == 1
    assert result["counts"] == {
        "acquisition_unaccounted": 1,
        "analysis_failed": 1,
        "awaiting_analysis": 1,
        "complete": 1,
        "decompilation_failed": 1,
        "download_failed": 1,
        "history_commit_failed": 1,
        "interrupted_or_running": 2,
        "pending_decompilation": 1,
    }
    assert len(result["items"]) == 10
    assert {item["status"] for item in result["items"]} == set(result["counts"])



def test_reconcile_marks_missing_successful_scan_output_incomplete(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    selected = manifest_row(1)
    database.write_manifest(RUN_ID, [selected])
    add_history(database, selected)
    add_processing(database, selected, jadx="success", apktool="success", scan="success")

    result = database.reconcile_run(RUN_ID)

    assert result["complete"] == 0
    assert result["counts"] == {"analysis_failed": 1}
    assert "findings file is missing" in result["items"][0]["detail"]


def test_manifest_writer_rejects_package_path_injection(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    selected = manifest_row(1)
    selected["package_id"] = "../outside"

    import pytest
    from apkworkbench.database.workspace import DatabaseError

    with pytest.raises(DatabaseError, match="invalid package ID"):
        database.write_manifest(RUN_ID, [selected])


def test_manifest_reader_rejects_package_path_injection(tmp_path):
    import csv
    import pytest
    from apkworkbench.database.workspace import DatabaseError
    from apkworkbench.database.workspace import MANIFEST_FIELDS

    database = WorkspaceDatabase(tmp_path)
    selected = manifest_row(1)
    path = database.write_manifest(RUN_ID, [selected])
    selected["package_id"] = "../outside"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerow(selected)

    with pytest.raises(DatabaseError, match="invalid package ID"):
        database.read_manifest(RUN_ID)


def test_reconcile_ignores_legacy_jadx_status_after_apktool_completion(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    awaiting = manifest_row(11)
    complete = manifest_row(12)
    database.write_manifest(RUN_ID, [awaiting, complete])
    add_history(database, awaiting)
    add_processing(
        database,
        awaiting,
        jadx="failed",
        apktool="success",
        scan="pending",
        error="Legacy JADX status is ignored by Apktool-only processing.",
    )
    add_history(database, complete)
    add_processing(
        database,
        complete,
        jadx="failed",
        apktool="success",
        scan="success",
        error="Legacy JADX status is ignored by Apktool-only processing.",
    )
    findings = (
        tmp_path / "results" / complete["package_id"] / "1"
        / complete["sha256"] / "trufflehog" / "findings.json"
    )
    findings.parent.mkdir(parents=True, exist_ok=True)
    findings.write_text("[]", encoding="utf-8")

    result = database.reconcile_run(RUN_ID)

    assert result["complete"] == 1
    assert result["counts"] == {
        "awaiting_analysis": 1,
        "complete": 1,
    }



def test_reconcile_counts_scanned_partial_apktool_output_as_complete_with_warning(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    selected = manifest_row(20)
    database.write_manifest(RUN_ID, [selected])
    add_history(database, selected)
    add_processing(
        database,
        selected,
        apktool="partial",
        scan="success",
        error="Apktool returned non-zero after writing files.",
    )
    findings = (
        tmp_path / "results" / selected["package_id"] / "1"
        / selected["sha256"] / "trufflehog" / "findings.json"
    )
    findings.parent.mkdir(parents=True, exist_ok=True)
    findings.write_text("[]", encoding="utf-8")

    result = database.reconcile_run(RUN_ID)

    assert result["complete"] == 1
    assert result["counts"] == {"complete_with_warnings": 1}
    assert "non-zero" in result["items"][0]["detail"]



def test_reconcile_requires_static_surface_result_for_new_pipeline_runs(tmp_path):
    import json

    database = WorkspaceDatabase(tmp_path)
    selected = manifest_row(30)
    database.write_manifest(RUN_ID, [selected])
    add_history(database, selected)
    add_processing(database, selected, apktool="success", scan="success")
    findings = (
        tmp_path / "results" / selected["package_id"] / "1"
        / selected["sha256"] / "trufflehog" / "findings.json"
    )
    findings.parent.mkdir(parents=True, exist_ok=True)
    findings.write_text("[]", encoding="utf-8")
    marker = tmp_path / "results" / "runs" / RUN_ID / "static-analysis-run.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(json.dumps({"run_id": RUN_ID, "status": "success"}), encoding="utf-8")

    result = database.reconcile_run(RUN_ID)

    assert result["complete"] == 0
    assert result["counts"] == {"static_analysis_failed": 1}
    assert result["items"][0]["static_analysis_status"] == "failed"


def test_reconcile_accepts_terminal_static_surface_result(tmp_path):
    import json

    database = WorkspaceDatabase(tmp_path)
    selected = manifest_row(31)
    database.write_manifest(RUN_ID, [selected])
    add_history(database, selected)
    add_processing(database, selected, apktool="success", scan="success")
    artifact_root = (
        tmp_path / "results" / selected["package_id"] / "1" / selected["sha256"]
    )
    findings = artifact_root / "trufflehog" / "findings.json"
    findings.parent.mkdir(parents=True, exist_ok=True)
    findings.write_text("[]", encoding="utf-8")
    static_result = artifact_root / "static-analysis.json"
    static_result.write_text(
        json.dumps({"schema_version": 1, "status": "success", "findings": []}),
        encoding="utf-8",
    )
    marker = tmp_path / "results" / "runs" / RUN_ID / "static-analysis-run.json"
    marker.parent.mkdir(parents=True)
    marker.write_text(
        json.dumps({"run_id": RUN_ID, "status": "success", "completed": 1}),
        encoding="utf-8",
    )

    result = database.reconcile_run(RUN_ID)

    assert result["complete"] == 1
    assert result["counts"] == {"complete": 1}
    assert result["items"][0]["static_analysis_status"] == "success"
