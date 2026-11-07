"""Sequential streaming APK downloads with size and SHA-256 verification."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import requests

from ..database.workspace import DatabaseError, WorkspaceDatabase, utc_now
from ..sources.fdroid import FdroidArtifact


_LOGGER = logging.getLogger("apkworkbench.acquisition")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")


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
        session: requests.Session | None = None,
    ):
        if timeout_seconds < 1 or chunk_size < 1:
            raise ValueError("timeout_seconds and chunk_size must be positive")
        self.database = database
        self.workspace = Path(workspace).expanduser()
        self.timeout_seconds = timeout_seconds
        self.chunk_size = chunk_size
        self.session = session or requests.Session()

    def destination_for(self, artifact: FdroidArtifact) -> Path:
        if not _PACKAGE_RE.fullmatch(artifact.package_id):
            raise DownloadError(f"Unsafe Android package ID: {artifact.package_id!r}")
        if artifact.version_code < 0 or artifact.size < 1:
            raise DownloadError("Artifact metadata contains an invalid version code or size.")
        return (
            self.workspace
            / "downloads"
            / artifact.package_id
            / str(artifact.version_code)
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

    def download(
        self,
        artifact: FdroidArtifact,
        *,
        run_id: str,
        index_sha256: str,
    ) -> DownloadResult:
        destination = self.destination_for(artifact)
        self._validate_download_url(artifact.download_url)
        destination.parent.mkdir(parents=True, exist_ok=True)
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

            response = self.session.get(
                artifact.download_url,
                stream=True,
                timeout=(min(15, self.timeout_seconds), self.timeout_seconds),
                allow_redirects=False,
                headers={
                    "User-Agent": "APK-Workbench/0.1 (+https://github.com/xdial9/apk-workbench)",
                    "Accept-Encoding": "identity",
                },
            )
            try:
                if response.status_code != 200:
                    if 300 <= response.status_code < 400:
                        raise DownloadError(
                            f"Refusing APK download redirect (HTTP {response.status_code})."
                        )
                    raise DownloadError(
                        f"Unexpected HTTP status downloading APK: {response.status_code}."
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError as exc:
                        raise DownloadError("APK response has an invalid Content-Length.") from exc
                    if declared != artifact.size:
                        raise DownloadError(
                            f"APK Content-Length mismatch: expected {artifact.size}, received {declared}."
                        )

                digest = hashlib.sha256()
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
            finally:
                response.close()

            actual_hash = digest.hexdigest()
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
                        "status": "failed",
                        "bytes_received": received,
                        "error": str(exc)[:1000],
                    }
                )
            except DatabaseError as log_error:
                _LOGGER.error("Could not append failed-attempt record: %s", log_error)
            if isinstance(exc, DownloadError):
                raise
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
