"""Google Play Store discovery and verified bundle acquisition.

This adapter intentionally uses the pinned playstore-cli 0.1.x Python API rather than
scraping its human-readable terminal output. The dependency is pinned because its API
is alpha and the adapter relies on its Play API/session/download modules.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from playstore_cli import download as play_download
from apkworkbench.sources.google_play_anonymous import (
    AnonymousGooglePlaySession,
    AnonymousGooglePlaySessionError,
)
from playstore_cli.api import (
    NotDownloadable,
    PlayApi,
    PlayApiError,
    certificate_hashes,
)

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
_MAX_RETRIES = 3


class GooglePlayError(RuntimeError):
    """Raised when Google Play discovery or acquisition fails."""


class GooglePlayUnavailableError(GooglePlayError):
    """Raised when a specific app is paid, incompatible, or unavailable for this Play device."""


class GooglePlayAuthenticationError(GooglePlayError):
    """Raised when an anonymous Google Play device session is unavailable."""


@dataclass(frozen=True)
class PlayApp:
    package_id: str
    title: str
    developer: str
    version_name: str
    version_code: int


@dataclass(frozen=True)
class PlayFile:
    name: str
    size: int
    sha256: str
    expected_algorithm: str
    expected_digest: str
    kind: str


@dataclass(frozen=True)
class PlayBundlePlan:
    app: PlayApp
    files: tuple[PlayFile, ...]
    signer_sha256: tuple[str, ...]
    _doc: Any
    _delivery: Any


@dataclass(frozen=True)
class AcquiredBundle:
    app: PlayApp
    directory: Path
    apk_files: tuple[Path, ...]
    obb_files: tuple[Path, ...]
    manifest_path: Path
    manifest_sha256: str


def _hex_from_b64url(value: str) -> str:
    if not value:
        return ""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii")).hex()


def _app_from_doc(doc: Any) -> PlayApp:
    package_id = str(getattr(doc, "docid", "") or "")
    if not _PACKAGE_RE.fullmatch(package_id):
        raise GooglePlayError(f"Google Play returned an invalid package ID: {package_id!r}")
    details = doc.details.appDetails
    return PlayApp(
        package_id=package_id,
        title=str(getattr(doc, "title", "") or package_id),
        developer=str(getattr(doc, "creator", "") or ""),
        version_name=str(getattr(details, "versionString", "") or ""),
        version_code=int(getattr(details, "versionCode", 0) or 0),
    )


class GooglePlaySource:
    """Google Play adapter using anonymously-issued device sessions."""

    def __init__(
        self,
        *,
        retry_backoff_seconds: float = 1.0,
        country: str = "US",
        arch: str = "arm64",
        profile: str | None = None,
        dispenser_url: str | None = None,
        anonymous_session: AnonymousGooglePlaySession | None = None,
    ):
        if retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds cannot be negative")
        self.retry_backoff_seconds = retry_backoff_seconds
        self._api: PlayApi | None = None
        self._anonymous_session = anonymous_session or AnonymousGooglePlaySession(
            country=country,
            arch=arch,
            profile=profile,
            dispenser_url=dispenser_url,
        )

    def _new_api(self, *, force_session: bool = False) -> PlayApi:
        try:
            return self._anonymous_session.new_api(force_refresh=force_session)
        except AnonymousGooglePlaySessionError as exc:
            raise GooglePlayAuthenticationError(str(exc)) from exc
        except Exception:
            raise GooglePlayAuthenticationError(
                "Could not initialise anonymous Google Play access."
            ) from None

    def _call(self, operation):
        if self._api is None:
            self._api = self._new_api()
        try:
            return operation(self._api)
        except PlayApiError as exc:
            if exc.status != 401:
                raise GooglePlayError(f"Google Play API request failed: {exc}") from exc
            self._api = self._new_api(force_session=True)
            try:
                return operation(self._api)
            except Exception as retry_exc:
                raise GooglePlayError(
                    f"Google Play API request failed after session renewal: {retry_exc}"
                ) from retry_exc
        except NotDownloadable as exc:
            raise GooglePlayUnavailableError(f"Google Play cannot deliver this app: {exc}") from exc
        except Exception as exc:
            raise GooglePlayError(f"Google Play request failed: {exc}") from exc

    def categories(self) -> list[tuple[str, str]]:
        """Return the two Play roots and all available app/game subcategories."""
        def fetch(api):
            values = [("APPLICATION", "Apps"), ("GAME", "Games")]
            for parent in ("APPLICATION", "GAME"):
                values.extend(api.categories(parent))
            unique: dict[str, str] = {}
            for category_id, name in values:
                unique.setdefault(str(category_id), str(name))
            return sorted(unique.items(), key=lambda item: item[0])
        return self._call(fetch)

    def search(self, query: str, *, limit: int = 516) -> list[PlayApp]:
        query = query.strip()
        if not query:
            raise ValueError("Search query cannot be empty")
        if limit < 1:
            raise ValueError("Search limit must be positive")
        docs = self._call(lambda api: api.search(query, limit))
        return [_app_from_doc(doc) for doc in docs if getattr(doc, "docid", "")]

    def top(self, category_id: str, *, limit: int = 200) -> list[PlayApp]:
        if not re.fullmatch(r"[A-Za-z0-9_]+", category_id):
            raise ValueError(f"Invalid Google Play category ID: {category_id!r}")
        if limit < 1:
            raise ValueError("Chart limit must be positive")
        docs = self._call(lambda api: api.top_chart(category_id, "free", limit))
        return [_app_from_doc(doc) for doc in docs if getattr(doc, "docid", "")]

    def discover(
        self,
        *,
        queries: tuple[str, ...] = (),
        category_ids: tuple[str, ...] | None = None,
        per_category_limit: int = 200,
        per_query_limit: int = 516,
        total_limit: int = 15000,
    ) -> list[PlayApp]:
        """Collect and de-duplicate Play search and top-free chart results."""
        if total_limit < 1:
            raise ValueError("total_limit must be positive")
        categories = list(category_ids) if category_ids is not None else [
            category_id for category_id, _ in self.categories()
        ]
        found: dict[str, PlayApp] = {}
        for query in queries:
            for app in self.search(query, limit=per_query_limit):
                found.setdefault(app.package_id, app)
                if len(found) >= total_limit:
                    return list(found.values())
        for category_id in categories:
            for app in self.top(category_id, limit=per_category_limit):
                found.setdefault(app.package_id, app)
                if len(found) >= total_limit:
                    return list(found.values())
        return list(found.values())

    def inspect(self, package_id: str, *, version_code: int | None = None) -> PlayBundlePlan:
        """Resolve delivery metadata and Play-provided hashes without downloading files."""
        if not _PACKAGE_RE.fullmatch(package_id):
            raise ValueError(f"Invalid Android package ID: {package_id!r}")
        doc, delivery = self._call(lambda api: api.app_delivery(package_id, version_code))
        if not getattr(doc, "docid", ""):
            raise GooglePlayUnavailableError(f"No Google Play listing was found for {package_id}.")
        app = _app_from_doc(doc)
        if version_code is not None:
            app = PlayApp(
                app.package_id, app.title, app.developer, app.version_name, int(version_code)
            )
        certificates = certificate_hashes(doc)
        signer_sha256 = tuple(sorted({sha256 for _sha1, sha256 in certificates}))
        raw_files = play_download.play_files(package_id, delivery)
        base_file = next((item for item in raw_files if item.name == "base.apk"), None)
        if base_file is None or not base_file.url:
            raise GooglePlayUnavailableError(
                f"Google Play has no downloadable delivery for {package_id} on this device profile."
            )
        files: list[PlayFile] = []
        for item in raw_files:
            name = str(item.name)
            if Path(name).name != name or name in {"", ".", ".."}:
                raise GooglePlayError(f"Google Play returned an unsafe bundle filename: {name!r}")
            if not (name.endswith((".apk", ".obb"))):
                raise GooglePlayError(f"Google Play returned an unsupported bundle component: {name!r}")
            if not item.url:
                raise GooglePlayError(f"Google Play delivery omitted the download URL for {name}")
            algorithm, expected = item.expected_digest()
            if name.endswith(".apk") and algorithm != "sha256":
                raise GooglePlayError(f"Play did not provide a SHA-256 hash for APK component {name}")
            expected_hex = _hex_from_b64url(expected)
            if not expected_hex:
                raise GooglePlayError(f"Play did not provide an integrity hash for {name}")
            files.append(
                PlayFile(
                    name=name,
                    size=int(item.size),
                    sha256=expected_hex if algorithm == "sha256" else "",
                    expected_algorithm=algorithm,
                    expected_digest=expected_hex,
                    kind="apk" if name.endswith(".apk") else "obb",
                )
            )
        if not any(item.kind == "apk" and item.name == "base.apk" for item in files):
            raise GooglePlayError("Google Play delivery did not include base.apk")
        return PlayBundlePlan(app, tuple(files), signer_sha256, doc, delivery)

    def download(
        self,
        plan: PlayBundlePlan,
        *,
        workspace: str | Path,
        run_id: str,
    ) -> AcquiredBundle:
        """Download every APK split and OBB; the upstream client verifies Play's hashes."""
        root = Path(workspace).expanduser().resolve()
        downloads_root = root / "downloads"
        downloads_root.mkdir(parents=True, exist_ok=True)
        if downloads_root.is_symlink():
            raise GooglePlayError("Downloads root must not be a symlink")
        directory = downloads_root / f"{plan.app.package_id}-{plan.app.version_code}"
        if directory.is_symlink():
            raise GooglePlayError(f"Refusing symlink bundle directory: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.resolve(strict=True).relative_to(downloads_root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise GooglePlayError("Bundle directory resolves outside the downloads workspace") from exc

        downloader = play_download.Downloader(plan._delivery)
        for item in plan.files:
            component_path = directory / item.name
            partial_path = component_path.with_name(component_path.name + ".part")
            if component_path.is_symlink() or partial_path.is_symlink():
                raise GooglePlayError(f"Refusing symlinked bundle component: {component_path}")
            for attempt in range(_MAX_RETRIES + 1):
                try:
                    upstream_file = next(
                        candidate for candidate in play_download.play_files(
                            plan.app.package_id, plan._delivery
                        ) if candidate.name == item.name
                    )
                    downloader.fetch(upstream_file, directory)
                    break
                except Exception as exc:
                    if attempt >= _MAX_RETRIES:
                        raise GooglePlayError(
                            f"Google Play download failed for {plan.app.package_id}/{item.name}: {exc}"
                        ) from exc
                    time.sleep(min(30.0, self.retry_backoff_seconds * (2 ** attempt)))

        file_rows: list[dict[str, Any]] = []
        apk_paths: list[Path] = []
        obb_paths: list[Path] = []
        for item in plan.files:
            path = directory / item.name
            if path.is_symlink() or not path.is_file():
                raise GooglePlayError(f"Downloaded bundle component is missing or unsafe: {path}")
            digest = hashlib.new(item.expected_algorithm)
            size = 0
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            if size != item.size or digest.hexdigest() != item.expected_digest:
                raise GooglePlayError(f"Post-download integrity verification failed: {item.name}")
            sha256 = _sha256_file(path)
            file_rows.append(
                {
                    "name": item.name,
                    "kind": item.kind,
                    "size": size,
                    "sha256": sha256,
                    "play_hash_algorithm": item.expected_algorithm,
                    "play_hash": item.expected_digest,
                    "play_hash_verified": True,
                }
            )
            (apk_paths if item.kind == "apk" else obb_paths).append(path)

        metadata = {
            "source": "google_play",
            "package_id": plan.app.package_id,
            "title": plan.app.title,
            "developer": plan.app.developer,
            "version_name": plan.app.version_name,
            "version_code": plan.app.version_code,
            "run_id": run_id,
            "signer_sha256": list(plan.signer_sha256),
            "files": file_rows,
            "downloaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        serialized = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        manifest_sha256 = hashlib.sha256(serialized).hexdigest()
        manifest_path = directory / "google-play-bundle.json"
        _atomic_write(manifest_path, serialized + b"\n")
        return AcquiredBundle(
            app=plan.app,
            directory=directory,
            apk_files=tuple(apk_paths),
            obb_files=tuple(obb_paths),
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, content: bytes) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
