"""Bounded HTTPS retrieval and pinned-signature verification for F-Droid indexes."""
from __future__ import annotations

import tempfile
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

    def fetch_verified_index(self) -> bytes:
        """Return index-v2 bytes only after the pinned detached signature is valid."""
        trusted = {
            "".join(str(item).split()).upper()
            for item in self.verifier.trusted_fingerprints
        }
        if self.signer_fingerprint not in trusted:
            raise FdroidRepositoryError(
                "The configured F-Droid signer fingerprint is not in the GPG trust allowlist."
            )

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
        with tempfile.TemporaryDirectory(prefix="apkworkbench-fdroid-") as temp_dir:
            temp_path = Path(temp_dir)
            index_path = temp_path / "index-v2.json"
            signature_path = temp_path / "index-v2.json.asc"
            index_path.write_bytes(index_data)
            signature_path.write_bytes(signature_data)
            try:
                verified = self.verifier.verify_detached_signature(
                    index_path, signature_path, self.signer_fingerprint
                )
            except GpgVerificationError as exc:
                raise FdroidRepositoryError(f"F-Droid index verification failed: {exc}") from exc

        if not verified:
            raise FdroidRepositoryError(
                "F-Droid index signature is invalid or was not made by the pinned primary key."
            )
        self._progress("F-Droid index signature: VERIFIED")
        return index_data
