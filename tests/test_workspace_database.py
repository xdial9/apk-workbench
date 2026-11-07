"""Tests for immutable manifests and append-only acquisition records."""
from __future__ import annotations

import csv

import pytest

from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase


def history_row(digest):
    return {
        "sha256": digest,
        "package_id": "org.example.app",
        "version_code": 1,
        "version_name": "1.0",
        "source": "fdroid",
        "download_url": "https://f-droid.org/repo/app.apk",
        "local_path": "/workspace/downloads/org.example.app/1/app.apk",
        "size": 10,
        "run_id": "run-id",
        "downloaded_at": "2026-11-07T12:00:00+00:00",
        "index_sha256": "b" * 64,
    }


def test_database_initializes_required_csv_files(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()

    assert database.history_path.is_file()
    assert database.attempts_path.is_file()
    assert database.processing_path.is_file()
    assert database.manifest_dir.is_dir()
    assert database.history_hashes() == set()


def test_history_is_append_only_and_hash_deduplicated(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    database.append_history(history_row("a" * 64))

    assert database.history_hashes() == {"a" * 64}
    with pytest.raises(DatabaseError, match="already present"):
        database.append_history(history_row("a" * 64))

    with database.history_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["sha256"] == "a" * 64


def test_manifest_is_published_complete_and_cannot_be_overwritten(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    row = {
        "run_id": "fixed-run",
        "selection_order": 1,
        "selected_at": "2026-11-07T12:00:00+00:00",
        "package_id": "org.example.app",
        "app_name": "Example",
        "version_code": 1,
        "version_name": "1.0",
        "source": "fdroid",
        "download_url": "https://f-droid.org/repo/app.apk",
        "sha256": "a" * 64,
        "size": 10,
        "signer_sha256": "",
        "local_path": "/workspace/app.apk",
        "index_sha256": "b" * 64,
    }

    path = database.write_manifest("fixed-run", [row])

    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["package_id"] == "org.example.app"
    assert path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(DatabaseError, match="will not be overwritten"):
        database.write_manifest("fixed-run", [row])


def test_malformed_existing_history_fails_closed(tmp_path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    database.history_path.write_text("sha256,unexpected\nabc,def\n", encoding="utf-8")

    with pytest.raises(DatabaseError, match="Unexpected CSV header"):
        database.history_hashes()
