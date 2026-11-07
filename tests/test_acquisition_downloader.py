"""Tests for sequential APK downloads and integrity enforcement."""
from __future__ import annotations

import csv
import hashlib

import pytest

from apkworkbench.acquisition.downloader import ArtifactDownloader, DownloadError
from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase
from apkworkbench.sources.fdroid import FdroidArtifact


PAYLOAD = b"APK Workbench verified test APK bytes"


class FakeResponse:
    def __init__(self, body, *, status_code=200, content_length=True):
        self.body = body
        self.status_code = status_code
        self.headers = (
            {"Content-Length": str(len(body))}
            if content_length
            else {}
        )
        self.closed = False

    def iter_content(self, chunk_size):
        assert chunk_size > 0
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset : offset + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def make_artifact(payload=PAYLOAD, *, digest=None, size=None, url=None):
    return FdroidArtifact(
        package_id="org.example.app",
        version_code=42,
        version_name="4.2",
        app_name="Example App",
        repository_path="org.example.app_42.apk",
        download_url=url or "https://f-droid.org/repo/org.example.app_42.apk",
        sha256=digest or hashlib.sha256(payload).hexdigest(),
        size=len(payload) if size is None else size,
        signer_sha256=("c" * 64,),
        metadata={},
    )


def make_downloader(tmp_path, response, database=None):
    database = database or WorkspaceDatabase(tmp_path)
    database.ensure()
    session = FakeSession(response)
    downloader = ArtifactDownloader(
        database,
        workspace=tmp_path,
        timeout_seconds=10,
        chunk_size=7,
        session=session,
    )
    return downloader, database, session


def test_download_streams_verifies_and_records_history(tmp_path):
    response = FakeResponse(PAYLOAD)
    downloader, database, session = make_downloader(tmp_path, response)
    artifact = make_artifact()

    result = downloader.download(
        artifact,
        run_id="run-123",
        index_sha256="d" * 64,
    )

    assert result.path.read_bytes() == PAYLOAD
    assert result.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert result.size == len(PAYLOAD)
    assert not result.reused_existing
    assert database.history_hashes() == {artifact.sha256}
    assert response.closed
    assert session.calls[0][1]["stream"] is True
    assert session.calls[0][1]["allow_redirects"] is False
    assert not list(result.path.parent.glob("*.part"))

    with database.attempts_path.open(encoding="utf-8", newline="") as handle:
        attempts = list(csv.DictReader(handle))
    assert len(attempts) == 1
    assert attempts[0]["status"] == "success"


def test_hash_mismatch_removes_partial_file_and_does_not_record_history(tmp_path):
    response = FakeResponse(PAYLOAD)
    downloader, database, _ = make_downloader(tmp_path, response)
    artifact = make_artifact(digest="0" * 64)

    with pytest.raises(DownloadError, match="SHA-256 mismatch"):
        downloader.download(artifact, run_id="run-123", index_sha256="d" * 64)

    assert database.history_hashes() == set()
    assert not (tmp_path / "downloads/org.example.app/42/app.apk").exists()
    assert not list((tmp_path / "downloads/org.example.app/42").glob("*.part"))


def test_size_mismatch_is_rejected(tmp_path):
    response = FakeResponse(PAYLOAD)
    downloader, database, _ = make_downloader(tmp_path, response)
    artifact = make_artifact(size=len(PAYLOAD) + 1)

    with pytest.raises(DownloadError, match="Content-Length mismatch"):
        downloader.download(artifact, run_id="run-123", index_sha256="d" * 64)

    assert database.history_hashes() == set()


def test_redirect_is_rejected(tmp_path):
    response = FakeResponse(b"", status_code=302)
    downloader, database, _ = make_downloader(tmp_path, response)

    with pytest.raises(DownloadError, match="redirect"):
        downloader.download(make_artifact(), run_id="run-123", index_sha256="d" * 64)

    assert database.history_hashes() == set()
    assert response.closed


def test_untrusted_download_url_is_rejected_before_request(tmp_path):
    response = FakeResponse(PAYLOAD)
    downloader, database, session = make_downloader(tmp_path, response)
    artifact = make_artifact(url="http://f-droid.org/repo/app.apk")

    with pytest.raises(DownloadError, match="HTTPS"):
        downloader.download(artifact, run_id="run-123", index_sha256="d" * 64)

    assert session.calls == []
    assert database.history_hashes() == set()


def test_existing_verified_file_is_reused_without_network_request(tmp_path):
    downloader, database, session = make_downloader(tmp_path, FakeResponse(PAYLOAD))
    artifact = make_artifact()
    destination = downloader.destination_for(artifact)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(PAYLOAD)

    result = downloader.download(
        artifact,
        run_id="run-123",
        index_sha256="d" * 64,
    )

    assert result.reused_existing
    assert result.path == destination
    assert session.calls == []
    assert database.history_hashes() == {artifact.sha256}


def test_existing_file_with_wrong_hash_is_never_overwritten(tmp_path):
    downloader, database, session = make_downloader(tmp_path, FakeResponse(PAYLOAD))
    artifact = make_artifact()
    destination = downloader.destination_for(artifact)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"not the expected APK")

    with pytest.raises(DownloadError, match="different content"):
        downloader.download(
            artifact,
            run_id="run-123",
            index_sha256="d" * 64,
        )

    assert destination.read_bytes() == b"not the expected APK"
    assert session.calls == []
    assert database.history_hashes() == set()



def test_successful_verified_download_remains_success_when_attempt_log_fails(tmp_path):
    response = FakeResponse(PAYLOAD)
    downloader, database, _ = make_downloader(tmp_path, response)
    artifact = make_artifact()

    def fail_attempt_log(_row):
        raise DatabaseError("attempt log is read-only")

    database.append_attempt = fail_attempt_log
    result = downloader.download(
        artifact,
        run_id="run-123",
        index_sha256="d" * 64,
    )

    assert result.path.read_bytes() == PAYLOAD
    assert database.history_hashes() == {artifact.sha256}



def test_history_commit_failure_leaves_verified_file_for_retry(tmp_path):
    response = FakeResponse(PAYLOAD)
    downloader, database, _ = make_downloader(tmp_path, response)
    artifact = make_artifact()

    def fail_history_commit(_row):
        raise DatabaseError("history is read-only")

    database.append_history = fail_history_commit
    with pytest.raises(DownloadError, match="verified file was left in place"):
        downloader.download(
            artifact,
            run_id="run-123",
            index_sha256="d" * 64,
        )

    destination = downloader.destination_for(artifact)
    assert destination.read_bytes() == PAYLOAD
    assert database.history_hashes() == set()
