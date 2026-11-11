"""Append-only acquisition records and immutable run manifests."""
from __future__ import annotations

import csv
import fcntl
import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from threading import local
from datetime import datetime, timezone
from pathlib import Path


class DatabaseError(RuntimeError):
    """Raised when a persistent database file is malformed or cannot be updated."""


HISTORY_FIELDS = [
    "sha256",
    "package_id",
    "app_name",
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
_LOCK_STATE = local()


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
        self.root = Path(workspace).expanduser().resolve()
        self.database_dir = self.root / "database"
        self.manifest_dir = self.database_dir / "run_manifests"
        self.history_path = self.database_dir / "download_history.csv"
        self.attempts_path = self.database_dir / "download_attempts.csv"
        self.processing_path = self.database_dir / "processing_status.csv"

    def _ensure_workspace_directories(self) -> None:
        """Create database directories only when they remain inside the workspace."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            if self.database_dir.is_symlink():
                raise DatabaseError("Refusing a symlinked workspace database directory.")
            self.database_dir.mkdir(parents=True, exist_ok=True)
            database_root = self.database_dir.resolve(strict=True)
            database_root.relative_to(self.root)

            if self.manifest_dir.is_symlink():
                raise DatabaseError("Refusing a symlinked run-manifest directory.")
            self.manifest_dir.mkdir(parents=True, exist_ok=True)
            self.manifest_dir.resolve(strict=True).relative_to(database_root)
        except DatabaseError:
            raise
        except (OSError, ValueError) as exc:
            raise DatabaseError(
                f"Workspace database directories must remain inside {self.root}: {exc}"
            ) from exc

    @contextmanager
    def _write_lock(self):
        """Serialize workspace reads and mutations across threads and processes."""
        self._ensure_workspace_directories()
        lock_path = self.database_dir / ".workspace.lock"
        if lock_path.is_symlink():
            raise DatabaseError("Refusing a symlinked workspace database lock.")
        key = str(self.database_dir.resolve())
        held = getattr(_LOCK_STATE, "held", None)
        if held is None:
            held = {}
            _LOCK_STATE.held = held
        state = held.get(key)
        if state is not None:
            # Keep a local reference to the state. A signal/exception during nested
            # unwinding must not turn a second dictionary lookup into a KeyError.
            state["depth"] += 1
            try:
                yield
            finally:
                state["depth"] -= 1
            return

        handle = None
        try:
            handle = lock_path.open("a+")
            os.chmod(lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            if handle is not None:
                handle.close()
            raise DatabaseError(f"Cannot acquire workspace database lock: {exc}") from exc
        except BaseException:
            # KeyboardInterrupt can arrive while flock is waiting. Never leak the
            # descriptor or leave a half-acquired lock behind.
            if handle is not None:
                handle.close()
            raise

        state = {"depth": 1, "handle": handle}
        held[key] = state
        try:
            yield
        finally:
            # Only remove the entry installed by this outermost acquisition.
            if held.get(key) is state:
                held.pop(key, None)
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    def ensure(self) -> None:
        self._ensure_workspace_directories()
        for path, fields in (
            (self.history_path, HISTORY_FIELDS),
            (self.attempts_path, ATTEMPT_FIELDS),
            (self.processing_path, PROCESSING_FIELDS),
        ):
            self._ensure_header(path, fields)

    @staticmethod
    def _ensure_header(path: Path, fields: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise DatabaseError(f"Refusing a symlinked database file: {path}")
        if path.exists() and not path.is_file():
            raise DatabaseError(f"Database path is not a regular file: {path}")
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
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise DatabaseError(f"Cannot secure database file {path}: {exc}") from exc
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

    def history_hashes(self, source: str | None = None) -> set[str]:
        self.ensure()
        with self._write_lock():
            hashes: set[str] = set()
            try:
                with self.history_path.open("r", encoding="utf-8", newline="") as handle:
                    for row in csv.DictReader(handle):
                        digest = (row.get("sha256") or "").strip().lower()
                        if source is not None and row.get("source") != source:
                            continue
                        if len(digest) != 64 or any(
                            char not in "0123456789abcdef" for char in digest
                        ):
                            raise DatabaseError(
                                f"Malformed SHA-256 value in {self.history_path}: {digest!r}"
                            )
                        hashes.add(digest)
            except OSError as exc:
                raise DatabaseError(f"Cannot read download history: {exc}") from exc
            return hashes

    def read_download_history(self) -> list[dict[str, str]]:
        self.ensure()
        with self._write_lock():
            try:
                with self.history_path.open("r", encoding="utf-8", newline="") as handle:
                    return list(csv.DictReader(handle))
            except OSError as exc:
                raise DatabaseError(f"Cannot read download history: {exc}") from exc

    def read_download_attempts(self) -> list[dict[str, str]]:
        self.ensure()
        with self._write_lock():
            try:
                with self.attempts_path.open("r", encoding="utf-8", newline="") as handle:
                    return list(csv.DictReader(handle))
            except OSError as exc:
                raise DatabaseError(f"Cannot read download attempts: {exc}") from exc

    def reconcile_run(self, run_id: str) -> dict[str, object]:
        """Account for every manifest entry using acquisition attempts and stage state."""
        manifest = self.read_manifest(run_id)
        history = self.read_download_history()
        attempts = self.read_download_attempts()
        processing = self.read_processing_status()

        history_by_hash = {row.get("sha256", "").lower(): row for row in history}
        results_root = self.root / "results"
        marker_dir = results_root / "runs" / run_id
        marker_path = marker_dir / "static-analysis-run.json"
        marker_components = (results_root, results_root / "runs", marker_dir, marker_path)
        surface_run_status = "legacy_not_required"
        if any(part.is_symlink() for part in marker_components):
            surface_run_status = "failed"
        elif marker_path.is_file():
            try:
                marker_payload = json.loads(marker_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                surface_run_status = "failed"
            else:
                candidate_status = marker_payload.get("status") if isinstance(marker_payload, dict) else None
                surface_run_status = (
                    candidate_status
                    if candidate_status in {"running", "success", "partial", "failed"}
                    else "failed"
                )
        elif marker_path.exists():
            surface_run_status = "failed"

        attempts_by_hash: dict[str, dict[str, str]] = {}
        for attempt in attempts:
            if attempt.get("run_id") == run_id and attempt.get("sha256"):
                attempts_by_hash[attempt["sha256"].lower()] = attempt

        counts: dict[str, int] = {}
        items: list[dict[str, str]] = []
        for selected in manifest:
            digest = selected["sha256"]
            acquired = history_by_hash.get(digest)
            attempt = attempts_by_hash.get(digest)
            state = processing.get(digest, {})
            detail = ""
            static_status = "not_run"
            if acquired is None:
                if attempt and attempt.get("status") == "persistence_failed":
                    outcome = "history_commit_failed"
                elif attempt and attempt.get("status") == "interrupted":
                    outcome = "interrupted_or_running"
                    detail = attempt.get("error", "")
                elif attempt and attempt.get("status") == "failed":
                    outcome = "download_failed"
                elif attempt and attempt.get("status") in {"success", "success_existing"}:
                    outcome = "history_missing"
                    detail = "A success attempt exists without an immutable history record."
                else:
                    outcome = "acquisition_unaccounted"
                    detail = "No verified acquisition history or terminal attempt record exists."
                if attempt:
                    detail = detail or attempt.get("error", "")
            elif (
                selected.get("source") not in {"google_play", "fdroid"}
                or acquired.get("source") != selected.get("source")
                or acquired.get("run_id") != run_id
                or acquired.get("package_id") != selected.get("package_id")
                or str(acquired.get("version_code", "")) != str(selected.get("version_code", ""))
            ):
                outcome = "acquisition_conflict"
                detail = "Acquisition history does not match the frozen manifest entry."
            else:
                apktool = state.get("apktool_status", "pending")
                scan = state.get("scan_status", "pending")
                static_path = (
                    self.root / "results" / selected["package_id"]
                    / str(selected["version_code"]) / digest / "static-analysis.json"
                )
                static_components = (
                    self.root / "results",
                    self.root / "results" / selected["package_id"],
                    self.root / "results" / selected["package_id"]
                    / str(selected["version_code"]),
                    self.root / "results" / selected["package_id"]
                    / str(selected["version_code"]) / digest,
                    static_path,
                )
                static_status = (
                    "legacy_not_required" if surface_run_status == "legacy_not_required"
                    else "running" if surface_run_status == "running"
                    else "failed"
                )
                if any(part.is_symlink() for part in static_components):
                    static_status = "failed"
                    detail = "Static-analysis evidence path contains a symlink."
                elif static_path.is_file():
                    try:
                        static_payload = json.loads(static_path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        static_status = "failed"
                        detail = "Static-analysis result is missing, unreadable, or malformed."
                    else:
                        if isinstance(static_payload, dict) and static_payload.get("status") in {"success", "partial"}:
                            static_status = static_payload["status"]
                        else:
                            static_status = "failed"
                            detail = "Static-analysis result does not contain a successful terminal status."
                elif static_path.exists():
                    static_status = "failed"
                    detail = "Static-analysis result path is not a regular file."
                elif surface_run_status in {"success", "partial"}:
                    static_status = "failed"
                    detail = "Surface-analysis run completed without a result for this acquired APK."

                if apktool == "failed":
                    outcome = "decompilation_failed"
                elif "running" in {apktool, scan}:
                    outcome = "interrupted_or_running"
                elif apktool in {"success", "partial"}:
                    if scan == "failed":
                        outcome = "analysis_failed"
                    elif scan == "success":
                        findings_path = (
                            self.root / "results" / selected["package_id"]
                            / str(selected["version_code"]) / digest
                            / "trufflehog" / "findings.json"
                        )
                        findings_components = (
                            self.root / "results" / selected["package_id"],
                            self.root / "results" / selected["package_id"]
                            / str(selected["version_code"]),
                            self.root / "results" / selected["package_id"]
                            / str(selected["version_code"]) / digest,
                            findings_path.parent,
                            findings_path,
                        )
                        if (
                            any(part.is_symlink() for part in findings_components)
                            or not findings_path.is_file()
                        ):
                            outcome = "analysis_failed"
                            detail = (
                                "Processing status says scan succeeded, but the complete "
                                "findings file is missing or unsafe."
                            )
                        elif static_status == "failed":
                            outcome = "static_analysis_failed"
                        elif static_status == "running":
                            outcome = "interrupted_or_running"
                            detail = detail or "Static APK surface analysis is still running or was interrupted."
                        elif apktool == "partial" or static_status == "partial":
                            outcome = "complete_with_warnings"
                        else:
                            # Runs predating the built-in surface stage remain compatible.
                            outcome = "complete"
                    else:
                        outcome = (
                            "awaiting_analysis_partial_decompilation"
                            if apktool == "partial"
                            else "awaiting_analysis"
                        )
                else:
                    outcome = "pending_decompilation"
                detail = detail or state.get("error", "")

            counts[outcome] = counts.get(outcome, 0) + 1
            items.append(
                {
                    "sha256": digest,
                    "package_id": selected.get("package_id", ""),
                    "version_code": str(selected.get("version_code", "")),
                    "status": outcome,
                    "static_analysis_status": static_status if acquired is not None else "not_run",
                    "detail": detail,
                }
            )

        return {
            "run_id": run_id,
            "total": len(manifest),
            "complete": counts.get("complete", 0) + counts.get("complete_with_warnings", 0),
            "counts": dict(sorted(counts.items())),
            "items": items,
        }

    def read_processing_status(self) -> dict[str, dict[str, str]]:
        self.ensure()
        with self._write_lock():
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
        with self._write_lock():
            existing = self.read_processing_status()
            current = existing.get(digest, {field: "" for field in PROCESSING_FIELDS})
            current.update({
                field: str(row.get(field, current.get(field, "")))
                for field in PROCESSING_FIELDS
            })
            current["sha256"] = digest
            current["updated_at"] = str(row.get("updated_at") or utc_now())
            existing[digest] = current

            fd, temporary_name = tempfile.mkstemp(
                prefix=".processing_status.", suffix=".tmp", dir=self.database_dir
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(
                        handle, fieldnames=PROCESSING_FIELDS, extrasaction="raise"
                    )
                    writer.writeheader()
                    for key in sorted(existing):
                        writer.writerow({
                            field: existing[key].get(field, "")
                            for field in PROCESSING_FIELDS
                        })
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
                raise DatabaseError(
                    f"Cannot atomically update processing status: {exc}"
                ) from exc
            finally:
                if temporary.exists():
                    temporary.unlink()

    def append_attempt(self, row: Mapping[str, object]) -> None:
        self.ensure()
        with self._write_lock():
            self._append_row(self.attempts_path, ATTEMPT_FIELDS, row)

    def append_history(self, row: Mapping[str, object]) -> None:
        if row.get("source") != "google_play":
            raise DatabaseError("Only Google Play Store acquisition records may be appended.")
        digest = str(row.get("sha256", "")).lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise DatabaseError("Refusing to append a malformed SHA-256 digest.")
        self.ensure()
        with self._write_lock():
            source = str(row.get("source", ""))
            existing = self.read_download_history()
            if any(
                item.get("sha256", "").lower() == digest and item.get("source", "") == source
                for item in existing
            ):
                raise DatabaseError(
                    f"SHA-256 {digest} is already present in immutable {source!r} download history."
                )
            self._append_row(self.history_path, HISTORY_FIELDS, row)

    def write_manifest(
        self,
        run_id: str,
        rows: Iterable[Mapping[str, object]],
    ) -> Path:
        """Atomically publish a new manifest; an existing run manifest is never replaced."""
        if not isinstance(run_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", run_id
        ):
            raise DatabaseError("Run ID must contain only letters, digits, and hyphens.")
        materialized_rows = list(rows)
        seen_hashes: set[str] = set()
        seen_orders: set[int] = set()
        for row in materialized_rows:
            if row.get("run_id") != run_id:
                raise DatabaseError("Run manifest row contains a mismatched run ID.")
            if row.get("source") != "google_play":
                raise DatabaseError("Only Google Play Store items may enter a run manifest.")
            if not str(row.get("download_url", "")).startswith("google-play://"):
                raise DatabaseError(
                    "Google Play manifest references must use google-play:// identifiers."
                )
            package_id = str(row.get("package_id", ""))
            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                raise DatabaseError(f"Run manifest contains an invalid package ID: {package_id!r}.")
            if not str(row.get("version_code", "")).isdigit():
                raise DatabaseError("Run manifest contains an invalid version code.")
            digest = str(row.get("sha256", "")).lower()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise DatabaseError(f"Run manifest contains a malformed SHA-256 value: {digest!r}.")
            if digest in seen_hashes:
                raise DatabaseError(f"Duplicate artifact SHA-256 in run manifest: {digest}")
            try:
                order = int(row.get("selection_order") or "")
                size = int(row.get("size") or 0)
            except (TypeError, ValueError) as exc:
                raise DatabaseError("Run manifest contains an invalid selection order or size.") from exc
            if order < 1 or order in seen_orders or size < 0:
                raise DatabaseError("Run manifest contains a duplicate order or invalid size.")
            seen_hashes.add(digest)
            seen_orders.add(order)

        self.ensure()
        with self._write_lock():
            self.ensure()
            destination = self.manifest_dir / f"run_{run_id}.csv"
            if destination.exists() or destination.is_symlink():
                raise DatabaseError(f"Run manifest already exists and will not be overwritten: {destination}")

            fd, temporary_name = tempfile.mkstemp(
                prefix=f".run_{run_id}.", suffix=".tmp", dir=self.manifest_dir
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, extrasaction="raise")
                    writer.writeheader()
                    for row in materialized_rows:
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
    
    

    def read_manifest(self, run_id: str) -> list[dict[str, str]]:
        """Read one immutable run manifest in selection order."""
        if not isinstance(run_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", run_id
        ):
            raise DatabaseError("Run ID must contain only letters, digits, and hyphens.")

        self.ensure()
        with self._write_lock():
            path = self.manifest_dir / f"run_{run_id}.csv"
            if path.is_symlink() or not path.is_file():
                raise DatabaseError(f"Run manifest does not exist or is not a regular file: {path}")

            rows: list[dict[str, str]] = []
            seen_hashes: set[str] = set()
            seen_orders: set[int] = set()
            try:
                with path.open("r", encoding="utf-8", newline="") as handle:
                    reader = csv.DictReader(handle)
                    if reader.fieldnames != MANIFEST_FIELDS:
                        raise DatabaseError(
                            f"Unexpected CSV header in {path}; expected {MANIFEST_FIELDS!r}, "
                            f"found {reader.fieldnames!r}."
                        )
                    for row in reader:
                        if row.get("run_id") != run_id:
                            raise DatabaseError(f"Run manifest contains a mismatched run ID: {path}")
                        source = row.get("source", "")
                        download_url = row.get("download_url", "")
                        valid_reference = (
                            source == "google_play" and download_url.startswith("google-play://")
                        ) or (
                            source == "fdroid" and download_url.startswith("https://")
                        )
                        if not valid_reference:
                            raise DatabaseError(f"Run manifest contains an unsupported source reference: {path}")
                        package_id = row.get("package_id", "")
                        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                            raise DatabaseError(f"Run manifest contains an invalid package ID: {package_id!r}.")
                        if not (row.get("version_code") or "").isdigit():
                            raise DatabaseError("Run manifest contains an invalid version code.")
                        digest = (row.get("sha256") or "").strip().lower()
                        if len(digest) != 64 or any(
                            char not in "0123456789abcdef" for char in digest
                        ):
                            raise DatabaseError(
                                f"Run manifest contains a malformed SHA-256 value: {digest!r}"
                            )
                        if digest in seen_hashes:
                            raise DatabaseError(f"Duplicate artifact SHA-256 in run manifest: {digest}")
                        try:
                            order = int(row.get("selection_order") or "")
                        except ValueError as exc:
                            raise DatabaseError(
                                f"Invalid selection order in run manifest: {row.get('selection_order')!r}"
                            ) from exc
                        if order < 1 or order in seen_orders:
                            raise DatabaseError(f"Duplicate or invalid manifest selection order: {order}")
                        row["sha256"] = digest
                        seen_hashes.add(digest)
                        seen_orders.add(order)
                        rows.append(row)
            except OSError as exc:
                raise DatabaseError(f"Cannot read run manifest {path}: {exc}") from exc

            rows.sort(key=lambda row: int(row["selection_order"]))
            return rows
