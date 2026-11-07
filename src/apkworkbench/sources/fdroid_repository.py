"""Bounded HTTPS retrieval and pinned-signature verification for F-Droid indexes."""
from __future__ import annotations

import hashlib
import os
import tempfile
import time
from pathlib import Path
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import requests

from ..security.gpg_verifier import GpgVerificationError, GpgVerifier


class FdroidRepositoryError(RuntimeError):
    """Raised when repository data cannot be safely retrieved or authenticated."""


class FdroidRepositoryClient:
    """Retrieve F-Droid index-v2 and authenticate it before returning its bytes.

    The public-key endpoint is only a transport source. Trust is anchored by the
    independently published full primary fingerprint and the verifier's allowlist.
    Redirects are rejected so the configured HTTPS endpoint cannot silently change
    hosts or downgrade transport.
    """

    def __init__(
        self,
        verifier: GpgVerifier,
        *,
        repository_url: str = "https://f-droid.org/repo",
        key_url: str = (
            "https://keyserver.ubuntu.com/pks/lookup?op=get&search="
            "0x37D2C98789D8311948394E3E41E7044E1DBA2E89"
        ),
        signer_fingerprint: str = "37D2C98789D8311948394E3E41E7044E1DBA2E89",
        timeout_seconds: int = 30,
        max_index_bytes: int = 128 * 1024 * 1024,
        max_signature_bytes: int = 1024 * 1024,
        max_key_bytes: int = 2 * 1024 * 1024,
        session: requests.Session | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.repository_url = self._validate_url(
            repository_url, field="repository_url", allow_query=False
        ).rstrip("/")
        self.key_url = self._validate_url(key_url, field="key_url", allow_query=True)
        self.verifier = verifier
        self.signer_fingerprint = self._normalize_fingerprint(signer_fingerprint)
        if timeout_seconds < 1:
            raise FdroidRepositoryError("timeout_seconds must be positive.")
        if min(max_index_bytes, max_signature_bytes, max_key_bytes) < 1:
            raise FdroidRepositoryError("All response-size limits must be positive.")
        self.timeout_seconds = timeout_seconds
        self.max_index_bytes = max_index_bytes
        self.max_signature_bytes = max_signature_bytes
        self.max_key_bytes = max_key_bytes
        self.session = session or requests.Session()
        self.progress_callback = progress_callback

    def _progress(self, message: str) -> None:
        if self.progress_callback is not None:
            self.progress_callback(message)

    @staticmethod
    def _validate_url(value: str, *, field: str, allow_query: bool) -> str:
        if not isinstance(value, str) or not value:
            raise FdroidRepositoryError(f"{field} must be a non-empty HTTPS URL.")
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (parsed.query and not allow_query)
        ):
            raise FdroidRepositoryError(
                f"{field} must be HTTPS without credentials or fragment"
                + ("." if allow_query else " or query.")
            )
        return value

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        normalized = "".join(value.split()).upper()
        if len(normalized) != 40 or any(char not in "0123456789ABCDEF" for char in normalized):
            raise FdroidRepositoryError("A full 40-character primary-key fingerprint is required.")
        return normalized

    def _fetch_limited(self, url: str, *, limit: int, label: str) -> bytes:
        self._progress(f"Fetching {label}...")
        try:
            response = self.session.get(
                url,
                stream=True,
                timeout=self.timeout_seconds,
                allow_redirects=False,
                headers={
                    "User-Agent": "APK-Workbench/0.1 (+https://github.com/xdial9/apk-workbench)",
                    "Accept-Encoding": "identity",
                },
            )
        except requests.RequestException as exc:
            raise FdroidRepositoryError(f"Could not retrieve {label}: {exc}") from exc

        try:
            status = getattr(response, "status_code", None)
            if status != 200:
                if status is not None and 300 <= status < 400:
                    raise FdroidRepositoryError(
                        f"Refusing redirect while retrieving {label} (HTTP {status})."
                    )
                raise FdroidRepositoryError(
                    f"Unexpected HTTP status retrieving {label}: {status}."
                )

            headers: Any = getattr(response, "headers", {})
            content_length = headers.get("Content-Length") if headers else None
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except (TypeError, ValueError) as exc:
                    raise FdroidRepositoryError(
                        f"Invalid Content-Length while retrieving {label}."
                    ) from exc
                if declared_size < 0 or declared_size > limit:
                    raise FdroidRepositoryError(
                        f"{label} exceeds the configured {limit}-byte limit."
                    )

            body = bytearray()
            next_progress = 8 * 1024 * 1024
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                if not isinstance(chunk, bytes):
                    raise FdroidRepositoryError(f"Non-binary response body while retrieving {label}.")
                body.extend(chunk)
                if len(body) > limit:
                    raise FdroidRepositoryError(
                        f"{label} exceeds the configured {limit}-byte limit."
                    )
                if len(body) >= next_progress:
                    self._progress(f"  {label}: {len(body):,} bytes received")
                    next_progress = ((len(body) // (8 * 1024 * 1024)) + 1) * (8 * 1024 * 1024)
            if not body:
                raise FdroidRepositoryError(f"Empty response while retrieving {label}.")
            self._progress(f"  {label}: received {len(body):,} bytes")
            return bytes(body)
        except requests.RequestException as exc:
            raise FdroidRepositoryError(f"Could not read {label}: {exc}") from exc
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    def _cache_paths(self, cache_dir: str | Path) -> tuple[Path, Path, Path]:
        directory = Path(cache_dir).expanduser()
        if directory.is_symlink():
            raise FdroidRepositoryError("Refusing to use a symlink as the F-Droid cache directory.")
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if directory.is_symlink() or not directory.is_dir():
                raise FdroidRepositoryError("F-Droid cache path is not a real directory.")
            os.chmod(directory, 0o700)
        except OSError as exc:
            raise FdroidRepositoryError(f"Cannot prepare F-Droid index cache: {exc}") from exc

        identity = hashlib.sha256(
            f"{self.repository_url}\n{self.signer_fingerprint}".encode("utf-8")
        ).hexdigest()
        return (
            directory,
            directory / f"{identity}.index-v2.json",
            directory / f"{identity}.index-v2.json.asc",
        )

    @staticmethod
    def _read_cache_file(path: Path, limit: int) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            payload = handle.read(limit + 1)
        if len(payload) > limit:
            raise FdroidRepositoryError(f"Cached file exceeds its configured {limit}-byte limit.")
        if not payload:
            raise FdroidRepositoryError("Cached F-Droid index material is empty.")
        return payload

    @staticmethod
    def _write_cache_file(path: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".apkworkbench-index-", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            raise FdroidRepositoryError(f"Cannot update F-Droid index cache: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def _verify_index_bytes(self, index_data: bytes, signature_data: bytes) -> bool:
        with tempfile.TemporaryDirectory(prefix="apkworkbench-fdroid-") as temp_dir:
            temp_path = Path(temp_dir)
            index_path = temp_path / "index-v2.json"
            signature_path = temp_path / "index-v2.json.asc"
            index_path.write_bytes(index_data)
            signature_path.write_bytes(signature_data)
            try:
                return self.verifier.verify_detached_signature(
                    index_path, signature_path, self.signer_fingerprint
                )
            except GpgVerificationError as exc:
                raise FdroidRepositoryError(f"F-Droid index verification failed: {exc}") from exc

    def _read_verified_cache(
        self, cache_dir: str | Path, cache_ttl_seconds: int
    ) -> bytes | None:
        directory, index_path, signature_path = self._cache_paths(cache_dir)
        if index_path.is_symlink() or signature_path.is_symlink():
            self._progress("Cached index contains a symlink; ignoring cached material.")
            return None
        if not index_path.is_file() or not signature_path.is_file():
            return None
        try:
            index_stat = index_path.stat()
            signature_stat = signature_path.stat()
            now = time.time()
            age = now - min(index_stat.st_mtime, signature_stat.st_mtime)
            if age < 0 or age > cache_ttl_seconds:
                self._progress("Cached F-Droid index has expired; retrieving a fresh copy.")
                return None
            if (
                index_stat.st_size < 1
                or index_stat.st_size > self.max_index_bytes
                or signature_stat.st_size < 1
                or signature_stat.st_size > self.max_signature_bytes
            ):
                self._progress("Cached F-Droid index exceeds configured bounds; ignoring it.")
                return None
            index_data = self._read_cache_file(index_path, self.max_index_bytes)
            signature_data = self._read_cache_file(signature_path, self.max_signature_bytes)
        except (OSError, FdroidRepositoryError) as exc:
            self._progress(f"Could not safely read cached F-Droid index ({exc}); retrieving a fresh copy.")
            return None

        self._progress("Found a recent F-Droid index cache; re-verifying its detached signature...")
        try:
            verified = self._verify_index_bytes(index_data, signature_data)
        except FdroidRepositoryError as exc:
            self._progress(f"Cached index verification failed ({exc}); retrieving a fresh copy.")
            return None
        if not verified:
            self._progress("Cached index signature is invalid; retrieving a fresh copy.")
            return None

        self._progress("Cached F-Droid index signature: VERIFIED")
        return index_data

    def fetch_verified_index(
        self,
        *,
        cache_dir: str | Path | None = None,
        cache_ttl_seconds: int = 21600,
        force_refresh: bool = False,
    ) -> bytes:
        """Return authenticated index bytes, using a locally re-verified cache when fresh."""
        trusted = {
            "".join(str(item).split()).upper()
            for item in self.verifier.trusted_fingerprints
        }
        if self.signer_fingerprint not in trusted:
            raise FdroidRepositoryError(
                "The configured F-Droid signer fingerprint is not in the GPG trust allowlist."
            )
        if cache_ttl_seconds < 0:
            raise FdroidRepositoryError("cache_ttl_seconds cannot be negative.")

        if cache_dir is not None and cache_ttl_seconds > 0 and not force_refresh:
            cached = self._read_verified_cache(cache_dir, cache_ttl_seconds)
            if cached is not None:
                return cached

        self._progress("Checking the pinned F-Droid signing key...")
        key_data = self._fetch_limited(
            self.key_url, limit=self.max_key_bytes, label="F-Droid public key"
        )
        try:
            imported_fingerprint = self.verifier.import_public_key(
                key_data, expected_fingerprint=self.signer_fingerprint
            )
        except GpgVerificationError as exc:
            raise FdroidRepositoryError(f"F-Droid public-key validation failed: {exc}") from exc
        if imported_fingerprint != self.signer_fingerprint:
            raise FdroidRepositoryError("Imported F-Droid key fingerprint did not match the pin.")

        self._progress("Pinned key confirmed. Retrieving the signed index and detached signature...")
        index_url = f"{self.repository_url}/index-v2.json"
        signature_url = f"{index_url}.asc"
        index_data = self._fetch_limited(
            index_url, limit=self.max_index_bytes, label="F-Droid index-v2.json"
        )
        signature_data = self._fetch_limited(
            signature_url, limit=self.max_signature_bytes, label="F-Droid index signature"
        )

        self._progress("Checking the detached OpenPGP signature...")
        verified = self._verify_index_bytes(index_data, signature_data)
        if not verified:
            raise FdroidRepositoryError(
                "F-Droid index signature is invalid or was not made by the pinned primary key."
            )

        self._progress("F-Droid index signature: VERIFIED")
        if cache_dir is not None and cache_ttl_seconds > 0:
            directory, index_path, signature_path = self._cache_paths(cache_dir)
            # The signature is published last. A partially replaced pair cannot
            # be accepted unless the detached signature also verifies.
            self._write_cache_file(index_path, index_data)
            self._write_cache_file(signature_path, signature_data)
            self._progress(
                f"Authenticated F-Droid index cached for {cache_ttl_seconds:,} seconds: {directory}"
            )
        return index_data
