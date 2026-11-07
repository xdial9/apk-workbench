"""Sequential streaming APK downloads with size and SHA-256 verification."""
from __future__ import annotations

import hashlib
import logging
import os
import signal
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests

from ..database.workspace import DatabaseError, WorkspaceDatabase, utc_now
from ..sources.fdroid import FdroidArtifact


_LOGGER = logging.getLogger("apkworkbench.acquisition")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
_RETRYABLE_HTTP_STATUSES = {408, 425, 429, 500, 502, 503, 504}


class DownloadError(RuntimeError):
    """Raised when an APK cannot be safely acquired and verified."""


@dataclass(frozen=True)
class DownloadResult:
    artifact: FdroidArtifact
    path: Path
    sha256: str
    size: int
    reused_existing: bool = False


class ArtifactDownloader:
    """Download one APK at a time and record only fully verified files."""

    def __init__(
        self,
        database: WorkspaceDatabase,
        *,
        workspace: str | Path,
        timeout_seconds: int = 60,
        chunk_size: int = 256 * 1024,
        max_retries: int = 3,
        retry_backoff_seconds: float = 1.0,
        session: requests.Session | None = None,
    ):
        if timeout_seconds < 1 or chunk_size < 1:
            raise ValueError("timeout_seconds and chunk_size must be positive")
        if max_retries < 0 or retry_backoff_seconds < 0:
            raise ValueError("max_retries and retry_backoff_seconds cannot be negative")
        self.database = database
        self.workspace = Path(workspace).expanduser().resolve()
        self.timeout_seconds = timeout_seconds
        self.chunk_size = chunk_size
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self.session = session or requests.Session()

    def destination_for(self, artifact: FdroidArtifact) -> Path:
        if not _PACKAGE_RE.fullmatch(artifact.package_id):
            raise DownloadError(f"Unsafe Android package ID: {artifact.package_id!r}")
        if artifact.version_code < 0 or artifact.size < 1:
            raise DownloadError("Artifact metadata contains an invalid version code or size.")
        digest = artifact.sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise DownloadError("Artifact metadata contains an invalid SHA-256 digest.")
        # Version codes can be shared by distinct APK binaries. Key the leaf
        # directory by the full digest so two APKs can never overwrite each other.
        return (
            self.workspace
            / "downloads"
            / artifact.package_id
            / str(artifact.version_code)
            / digest
            / "app.apk"
        )

    @staticmethod
    def _validate_download_url(url: str) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise DownloadError("APK download URL must be HTTPS without credentials or fragment.")

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(60.0, max(0.0, float(retry_after)))
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after)
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=timezone.utc)
                    return min(
                        60.0,
                        max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds()),
                    )
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(30.0, self.retry_backoff_seconds * (2**attempt))

    def _stream_to_temporary(
        self, artifact: FdroidArtifact, destination: Path
    ) -> tuple[Path, str, int]:
        """Retry a complete bounded response stream, including mid-body interruptions."""
        request_headers = {
            "User-Agent": "APK-Workbench/0.1 (+https://github.com/xdial9/apk-workbench)",
            "Accept-Encoding": "identity",
        }
        previous_sigterm = None

        def handle_sigterm(signum, _frame):
            raise KeyboardInterrupt(f"received signal {signum}")

        try:
            previous_sigterm = signal.signal(signal.SIGTERM, handle_sigterm)
        except ValueError:
            # Signal handlers can only be installed from the main thread.
            pass

        try:
            for attempt in range(self.max_retries + 1):
                response = None
                temporary = None
                received = 0
                digest = hashlib.sha256()
                try:
                    response = self.session.get(
                        artifact.download_url,
                        stream=True,
                        timeout=(min(15, self.timeout_seconds), self.timeout_seconds),
                        allow_redirects=False,
                        headers=request_headers,
                    )
                    status = response.status_code
                    if status in _RETRYABLE_HTTP_STATUSES and attempt < self.max_retries:
                        retry_after = response.headers.get("Retry-After")
                        response.close()
                        response = None
                        time.sleep(self._retry_delay(attempt, retry_after))
                        continue
                    if status != 200:
                        if 300 <= status < 400:
                            raise DownloadError(
                                f"Refusing APK download redirect (HTTP {status})."
                            )
                        raise DownloadError(f"Unexpected HTTP status downloading APK: {status}.")

                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        try:
                            declared = int(content_length)
                        except ValueError as exc:
                            raise DownloadError(
                                "APK response has an invalid Content-Length."
                            ) from exc
                        if declared != artifact.size:
                            raise DownloadError(
                                f"APK Content-Length mismatch: expected {artifact.size}, "
                                f"received {declared}."
                            )

                    fd, temp_name = tempfile.mkstemp(
                        prefix=".app.apk.", suffix=".part", dir=destination.parent
                    )
                    temporary = Path(temp_name)
                    with os.fdopen(fd, "wb") as output:
                        for chunk in response.iter_content(chunk_size=self.chunk_size):
                            if not chunk:
                                continue
                            received += len(chunk)
                            if received > artifact.size:
                                raise DownloadError(
                                    f"APK exceeded advertised size ({artifact.size} bytes)."
                                )
                            digest.update(chunk)
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    return temporary, digest.hexdigest(), received
                except requests.RequestException:
                    if temporary is not None and temporary.exists():
                        temporary.unlink()
                        temporary = None
                    if attempt >= self.max_retries:
                        raise
                    retry_after = (
                        response.headers.get("Retry-After") if response is not None else None
                    )
                    time.sleep(self._retry_delay(attempt, retry_after))
                except KeyboardInterrupt:
                    if temporary is not None and temporary.exists():
                        temporary.unlink()
                    raise
                finally:
                    if response is not None:
                        response.close()
        finally:
            if previous_sigterm is not None:
                signal.signal(signal.SIGTERM, previous_sigterm)

        raise DownloadError("APK download retry loop ended without a verified stream.")

    def download(
        self,
        artifact: FdroidArtifact,
        *,
        run_id: str,
        index_sha256: str,
    ) -> DownloadResult:
        destination = self.destination_for(artifact)
        self._validate_download_url(artifact.download_url)
        downloads_root = self.workspace / "downloads"
        downloads_root.mkdir(parents=True, exist_ok=True)
        try:
            resolved_downloads_root = downloads_root.resolve(strict=True)
            resolved_downloads_root.relative_to(self.workspace)
        except (OSError, ValueError) as exc:
            raise DownloadError("Downloads directory resolves outside the configured workspace.") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            destination.parent.resolve(strict=True).relative_to(resolved_downloads_root)
        except (OSError, ValueError) as exc:
            raise DownloadError("APK destination resolves outside the downloads workspace.") from exc
        if destination.is_symlink():
            raise DownloadError(f"Refusing to use a symlink as an APK destination: {destination}")
        started = utc_now()
        temporary: Path | None = None
        received = 0

        try:
            if destination.exists():
                existing_hash, existing_size = self._hash_file(destination)
                if existing_hash != artifact.sha256 or existing_size != artifact.size:
                    raise DownloadError(
                        f"Destination already exists with different content: {destination}"
                    )
                self._record_success(
                    artifact, destination, run_id, index_sha256, existing_hash, existing_size
                )
                try:
                    self.database.append_attempt(
                        {
                            "timestamp": started,
                            "run_id": run_id,
                            "sha256": artifact.sha256,
                            "package_id": artifact.package_id,
                            "download_url": artifact.download_url,
                            "status": "success_existing",
                            "bytes_received": existing_size,
                            "error": "",
                        }
                    )
                except DatabaseError as log_error:
                    _LOGGER.warning("APK is verified and in history, but success attempt logging failed: %s", log_error)
                return DownloadResult(
                    artifact, destination, existing_hash, existing_size, reused_existing=True
                )

            temporary, actual_hash, received = self._stream_to_temporary(
                artifact, destination
            )


            if received != artifact.size:
                raise DownloadError(
                    f"APK size mismatch: expected {artifact.size}, received {received}."
                )
            if actual_hash != artifact.sha256.lower():
                raise DownloadError(
                    f"APK SHA-256 mismatch: expected {artifact.sha256}, received {actual_hash}."
                )
            if destination.exists():
                raise DownloadError(f"Refusing to overwrite existing APK: {destination}")
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
            temporary = None
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

            self._record_success(
                artifact, destination, run_id, index_sha256, actual_hash, received
            )
            try:
                self.database.append_attempt(
                    {
                        "timestamp": started,
                        "run_id": run_id,
                        "sha256": artifact.sha256,
                        "package_id": artifact.package_id,
                        "download_url": artifact.download_url,
                        "status": "success",
                        "bytes_received": received,
                        "error": "",
                    }
                )
            except DatabaseError as log_error:
                _LOGGER.warning("APK is verified and in history, but success attempt logging failed: %s", log_error)
            return DownloadResult(artifact, destination, actual_hash, received)

        except KeyboardInterrupt:
            if temporary is not None and temporary.exists():
                temporary.unlink()
            try:
                self.database.append_attempt(
                    {
                        "timestamp": started,
                        "run_id": run_id,
                        "sha256": artifact.sha256,
                        "package_id": artifact.package_id,
                        "download_url": artifact.download_url,
                        "status": "interrupted",
                        "bytes_received": received,
                        "error": "Download interrupted; temporary file removed.",
                    }
                )
            except DatabaseError as log_error:
                _LOGGER.error("Could not append interrupted-attempt record: %s", log_error)
            raise
        except Exception as exc:
            if temporary is not None and temporary.exists():
                temporary.unlink()
            try:
                self.database.append_attempt(
                    {
                        "timestamp": started,
                        "run_id": run_id,
                        "sha256": artifact.sha256,
                        "package_id": artifact.package_id,
                        "download_url": artifact.download_url,
                        "status": (
                            "persistence_failed"
                            if isinstance(exc, DatabaseError)
                            else "failed"
                        ),
                        "bytes_received": received,
                        "error": str(exc)[:1000],
                    }
                )
            except DatabaseError as log_error:
                _LOGGER.error("Could not append failed-attempt record: %s", log_error)
            if isinstance(exc, DownloadError):
                raise
            if isinstance(exc, DatabaseError):
                raise DatabaseError(
                    "A verified APK is present, but its acquisition-history record could not "
                    f"be committed: {exc}. Stop this acquisition run and repair the workspace "
                    "database before retrying."
                ) from exc
            if isinstance(exc, requests.RequestException):
                raise DownloadError(f"APK network request failed: {exc}") from exc
            if isinstance(exc, OSError):
                raise DownloadError(f"APK local file operation failed: {exc}") from exc
            raise

    @staticmethod
    def _hash_file(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        return digest.hexdigest(), size

    def _record_success(
        self,
        artifact: FdroidArtifact,
        destination: Path,
        run_id: str,
        index_sha256: str,
        digest: str,
        size: int,
    ) -> None:
        self.database.append_history(
            {
                "sha256": digest,
                "package_id": artifact.package_id,
                "app_name": artifact.app_name or "",
                "version_code": artifact.version_code,
                "version_name": artifact.version_name or "",
                "source": "fdroid",
                "download_url": artifact.download_url,
                "local_path": str(destination),
                "size": size,
                "run_id": run_id,
                "downloaded_at": utc_now(),
                "index_sha256": index_sha256,
            }
        )
