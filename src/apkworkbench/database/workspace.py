"""Append-only acquisition records and immutable run manifests."""
from __future__ import annotations

import csv
import os
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path


class DatabaseError(RuntimeError):
    """Raised when a persistent database file is malformed or cannot be updated."""


HISTORY_FIELDS = [
    "sha256",
    "package_id",
    "version_code",
    "version_name",
    "source",
    "download_url",
    "local_path",
    "size",
    "run_id",
    "downloaded_at",
    "index_sha256",
]
PROCESSING_FIELDS = [
    "sha256",
    "package_id",
    "version_code",
    "jadx_status",
    "apktool_status",
    "scan_status",
    "updated_at",
    "error",
]
ATTEMPT_FIELDS = [
    "timestamp",
    "run_id",
    "sha256",
    "package_id",
    "download_url",
    "status",
    "bytes_received",
    "error",
]
MANIFEST_FIELDS = [
    "run_id",
    "selection_order",
    "selected_at",
    "package_id",
    "app_name",
    "version_code",
    "version_name",
    "source",
    "download_url",
    "sha256",
    "size",
    "signer_sha256",
    "local_path",
    "index_sha256",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class WorkspaceDatabase:
    """Manage the workspace CSV records with append-only and atomic semantics."""

    def __init__(self, workspace: str | Path):
        self.root = Path(workspace).expanduser()
        self.database_dir = self.root / "database"
        self.manifest_dir = self.database_dir / "run_manifests"
        self.history_path = self.database_dir / "download_history.csv"
        self.attempts_path = self.database_dir / "download_attempts.csv"
        self.processing_path = self.database_dir / "processing_status.csv"

    def ensure(self) -> None:
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.database_dir.mkdir(parents=True, exist_ok=True)
        for path, fields in (
            (self.history_path, HISTORY_FIELDS),
            (self.attempts_path, ATTEMPT_FIELDS),
            (self.processing_path, PROCESSING_FIELDS),
        ):
            self._ensure_header(path, fields)

    @staticmethod
    def _ensure_header(path: Path, fields: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            try:
                with path.open("x", encoding="utf-8", newline="") as handle:
                    csv.writer(handle).writerow(fields)
                    handle.flush()
                    os.fsync(handle.fileno())
            except FileExistsError:
                pass
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                header = next(csv.reader(handle), None)
        except OSError as exc:
            raise DatabaseError(f"Cannot read database file {path}: {exc}") from exc
        if header != fields:
            raise DatabaseError(
                f"Unexpected CSV header in {path}; expected {fields!r}, found {header!r}."
            )

    @staticmethod
    def _append_row(path: Path, fields: list[str], row: Mapping[str, object]) -> None:
        WorkspaceDatabase._ensure_header(path, fields)
        try:
            with path.open("a", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="raise")
                writer.writerow({field: row.get(field, "") for field in fields})
                handle.flush()
                os.fsync(handle.fileno())
        except (OSError, csv.Error) as exc:
            raise DatabaseError(f"Cannot append to {path}: {exc}") from exc

    def history_hashes(self) -> set[str]:
        self.ensure()
        hashes: set[str] = set()
        try:
            with self.history_path.open("r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    digest = (row.get("sha256") or "").strip().lower()
                    if len(digest) != 64:
                        raise DatabaseError(
                            f"Malformed SHA-256 value in {self.history_path}: {digest!r}"
                        )
                    hashes.add(digest)
        except OSError as exc:
            raise DatabaseError(f"Cannot read download history: {exc}") from exc
        return hashes

    def read_download_history(self) -> list[dict[str, str]]:
        self.ensure()
        try:
            with self.history_path.open("r", encoding="utf-8", newline="") as handle:
                return list(csv.DictReader(handle))
        except OSError as exc:
            raise DatabaseError(f"Cannot read download history: {exc}") from exc

    def read_processing_status(self) -> dict[str, dict[str, str]]:
        self.ensure()
        try:
            with self.processing_path.open("r", encoding="utf-8", newline="") as handle:
                return {
                    row["sha256"]: row
                    for row in csv.DictReader(handle)
                    if row.get("sha256")
                }
        except OSError as exc:
            raise DatabaseError(f"Cannot read processing status: {exc}") from exc

    def update_processing_status(self, row: Mapping[str, object]) -> None:
        """Atomically replace mutable processing state keyed by artifact SHA-256."""
        digest = str(row.get("sha256", "")).lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise DatabaseError("Refusing to update processing status with malformed SHA-256.")
        self.ensure()
        existing = self.read_processing_status()
        current = existing.get(digest, {field: "" for field in PROCESSING_FIELDS})
        current.update({field: str(row.get(field, current.get(field, ""))) for field in PROCESSING_FIELDS})
        current["sha256"] = digest
        current["updated_at"] = str(row.get("updated_at") or utc_now())
        existing[digest] = current

        fd, temporary_name = tempfile.mkstemp(
            prefix=".processing_status.", suffix=".tmp", dir=self.database_dir
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=PROCESSING_FIELDS, extrasaction="raise")
                writer.writeheader()
                for key in sorted(existing):
                    writer.writerow({field: existing[key].get(field, "") for field in PROCESSING_FIELDS})
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.processing_path)
            directory_fd = os.open(self.database_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            raise DatabaseError(f"Cannot atomically update processing status: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def append_attempt(self, row: Mapping[str, object]) -> None:
        self._append_row(self.attempts_path, ATTEMPT_FIELDS, row)

    def append_history(self, row: Mapping[str, object]) -> None:
        digest = str(row.get("sha256", "")).lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise DatabaseError("Refusing to append a malformed SHA-256 digest.")
        if digest in self.history_hashes():
            raise DatabaseError(f"SHA-256 {digest} is already present in immutable download history.")
        self._append_row(self.history_path, HISTORY_FIELDS, row)

    def write_manifest(
        self,
        run_id: str,
        rows: Iterable[Mapping[str, object]],
    ) -> Path:
        """Atomically publish a new manifest; an existing run manifest is never replaced."""
        self.ensure()
        destination = self.manifest_dir / f"run_{run_id}.csv"
        if destination.exists():
            raise DatabaseError(f"Run manifest already exists and will not be overwritten: {destination}")

        fd, temporary_name = tempfile.mkstemp(
            prefix=f".run_{run_id}.", suffix=".tmp", dir=self.manifest_dir
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, extrasaction="raise")
                writer.writeheader()
                for row in rows:
                    writer.writerow({field: row.get(field, "") for field in MANIFEST_FIELDS})
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            # A hard link publishes the completed file atomically and refuses overwrite.
            os.link(temporary, destination)
            temporary.unlink()
            directory_fd = os.open(self.manifest_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except FileExistsError as exc:
            raise DatabaseError(f"Run manifest already exists: {destination}") from exc
        except OSError as exc:
            raise DatabaseError(f"Cannot publish run manifest {destination}: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()
        return destination
