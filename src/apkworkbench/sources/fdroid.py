"""Strict parser for authenticated F-Droid index-v2 JSON.

Callers must verify the detached OpenPGP signature before passing index bytes here.
F-Droid index-v2 maps each package version entry by the APK's SHA-256, not
by versionCode. APK file names are repository-root-relative and commonly
begin with one leading slash.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit


class FdroidIndexError(ValueError):
    """Raised when an F-Droid index is malformed or unsafe."""


_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")


@dataclass(frozen=True)
class FdroidArtifact:
    package_id: str
    version_code: int
    version_name: str | None
    app_name: str | None
    repository_path: str
    download_url: str
    sha256: str
    size: int
    signer_sha256: tuple[str, ...]
    metadata: dict[str, Any]


class FdroidIndexParser:
    """Parse package/version records from F-Droid's index-v2 schema."""

    def __init__(self, repository_url: str = "https://f-droid.org/repo"):
        parsed = urlsplit(repository_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise FdroidIndexError(
                "Repository URL must be HTTPS without credentials, query, or fragment."
            )
        self.repository_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
        )

    @staticmethod
    def _normalize_repository_path(repository_path: str) -> str:
        parsed = urlsplit(repository_path)
        raw_path = parsed.path
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or raw_path.startswith("//")
            or "\\" in raw_path
            or "%" in raw_path
            or any(ord(char) < 32 or ord(char) == 127 for char in raw_path)
        ):
            raise FdroidIndexError(
                f"Unsafe repository artifact path: {repository_path!r}"
            )

        # index-v2 file names are root-relative; F-Droid normally serializes
        # these with exactly one leading slash (e.g. /org.example_123.apk).
        path = raw_path.removeprefix("/")
        parts = path.split("/")
        if not path or any(part in {"", ".", ".."} for part in parts):
            raise FdroidIndexError(
                f"Unsafe repository artifact path: {repository_path!r}"
            )
        return path

    def _download_url(self, repository_path: str) -> str:
        path = self._normalize_repository_path(repository_path)
        encoded_path = quote(path, safe="/-._~")
        return f"{self.repository_url}/{encoded_path}"

    @staticmethod
    def _localized_name(value: Any) -> str | None:
        if isinstance(value, str):
            return value
        if not isinstance(value, dict):
            return None
        for locale in ("en-US", "en"):
            localized = value.get(locale)
            if isinstance(localized, str) and localized:
                return localized
        for locale in sorted(value):
            localized = value[locale]
            if isinstance(localized, str) and localized:
                return localized
        return None

    @staticmethod
    def _signer_fingerprints(manifest: dict[str, Any]) -> tuple[str, ...]:
        signer = manifest.get("signer")
        if signer is None:
            return ()
        if not isinstance(signer, dict):
            raise FdroidIndexError("Version manifest signer field must be an object.")
        values = signer.get("sha256", [])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            raise FdroidIndexError("Signer sha256 field must be a string or list.")
        fingerprints = []
        for value in values:
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise FdroidIndexError("APK signer SHA-256 fingerprint is malformed.")
            fingerprints.append(value.lower())
        return tuple(fingerprints)

    def parse(self, index_data: bytes | str) -> list[FdroidArtifact]:
        """Return normalized APK artifacts from already-authenticated index JSON."""
        try:
            root = json.loads(index_data)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise FdroidIndexError(f"Index is not valid UTF-8 JSON: {exc}") from exc
        if not isinstance(root, dict) or not isinstance(root.get("packages"), dict):
            raise FdroidIndexError("Index root must contain a packages object.")

        artifacts: list[FdroidArtifact] = []
        for package_id, package in root["packages"].items():
            if not isinstance(package_id, str) or not _PACKAGE_RE.fullmatch(package_id):
                raise FdroidIndexError(f"Invalid Android package ID: {package_id!r}")
            if not isinstance(package, dict):
                raise FdroidIndexError(f"Package {package_id} entry must be an object.")
            versions = package.get("versions")
            if not isinstance(versions, dict):
                raise FdroidIndexError(f"Package {package_id} has no versions object.")
            metadata = package.get("metadata", {})
            if not isinstance(metadata, dict):
                raise FdroidIndexError(f"Package {package_id} metadata must be an object.")
            app_name = self._localized_name(metadata.get("name"))

            for version_key, version in versions.items():
                if not isinstance(version_key, str) or not _SHA256_RE.fullmatch(version_key):
                    raise FdroidIndexError(
                        f"Package {package_id} version map key must be an APK SHA-256."
                    )
                if not isinstance(version, dict):
                    raise FdroidIndexError(
                        f"Package {package_id} version {version_key} is malformed."
                    )
                file_info = version.get("file")
                manifest = version.get("manifest")
                if not isinstance(file_info, dict) or not isinstance(manifest, dict):
                    raise FdroidIndexError(
                        f"Package {package_id} version {version_key} lacks file/manifest."
                    )
                repository_path = file_info.get("name")
                digest = file_info.get("sha256")
                size = file_info.get("size")
                raw_version_code = manifest.get("versionCode")
                version_name = manifest.get("versionName")
                if not isinstance(repository_path, str):
                    raise FdroidIndexError(f"Package {package_id} has no artifact path.")
                if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                    raise FdroidIndexError(
                        f"Package {package_id} has an invalid APK SHA-256."
                    )
                if version_key.lower() != digest.lower():
                    raise FdroidIndexError(
                        f"Package {package_id} version map key does not match file SHA-256."
                    )
                if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
                    raise FdroidIndexError(f"Package {package_id} has an invalid APK size.")
                if isinstance(raw_version_code, bool):
                    raise FdroidIndexError(
                        f"Package {package_id} has an invalid versionCode."
                    )
                try:
                    version_code = int(raw_version_code)
                except (TypeError, ValueError) as exc:
                    raise FdroidIndexError(
                        f"Package {package_id} has an invalid versionCode."
                    ) from exc
                if version_code < 0:
                    raise FdroidIndexError(
                        f"Package {package_id} has a negative versionCode."
                    )
                if version_name is not None and not isinstance(version_name, str):
                    raise FdroidIndexError(
                        f"Package {package_id} has an invalid versionName."
                    )

                normalized_path = self._normalize_repository_path(repository_path)
                artifacts.append(
                    FdroidArtifact(
                        package_id=package_id,
                        version_code=version_code,
                        version_name=version_name,
                        app_name=app_name,
                        repository_path=normalized_path,
                        download_url=self._download_url(repository_path),
                        sha256=digest.lower(),
                        size=size,
                        signer_sha256=self._signer_fingerprints(manifest),
                        metadata=metadata,
                    )
                )
        return artifacts


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Calculate a file's SHA-256 digest without loading it all into memory."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
