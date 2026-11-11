"""Apktool-only decompilation for verified local APKs."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..database.workspace import WorkspaceDatabase, utc_now


class DecompilationError(RuntimeError):
    """Raised when a decompilation input or execution step is invalid."""


@dataclass(frozen=True)
class DecompilationSummary:
    examined: int
    completed: int
    failed: int
    skipped: int
    partial: int = 0


class DecompilationRunner:
    """Re-verify each acquired APK and decode it with Apktool."""

    def __init__(
        self,
        database: WorkspaceDatabase,
        *,
        workspace: str | Path,
        apktool_executable: str = "apktool",
        timeout_seconds: int = 3600,
        logger: logging.Logger | None = None,
        progress: Callable[[str], None] | None = None,
    ):
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.database = database
        self.workspace = Path(workspace).expanduser().resolve()
        self.download_root = self.workspace / "downloads"
        self.results_root = self.workspace / "results"
        self.apktool_executable = apktool_executable
        self.timeout_seconds = timeout_seconds
        self.logger = logger or logging.getLogger("apkworkbench.decompilation")
        self.progress = progress

    @staticmethod
    def _sha256(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        return digest.hexdigest(), size

    def _validated_apk_path(self, row: dict[str, str]) -> Path:
        raw_path = row.get("local_path", "")
        if not raw_path:
            raise DecompilationError("Download history record has no local_path.")
        candidate_path = Path(raw_path).expanduser()
        if candidate_path.is_symlink():
            raise DecompilationError("Acquired APK path must not be a symlink.")
        apk_path = candidate_path.resolve(strict=True)
        try:
            apk_path.relative_to(self.download_root)
        except ValueError as exc:
            raise DecompilationError(
                f"Refusing to process APK outside the downloads workspace: {apk_path}"
            ) from exc
        if not apk_path.is_file() or apk_path.suffix.lower() != ".apk":
            raise DecompilationError(f"Acquired artifact is not a regular APK file: {apk_path}")

        expected_hash = row.get("sha256", "").lower()
        if len(expected_hash) != 64 or any(char not in "0123456789abcdef" for char in expected_hash):
            raise DecompilationError("Download history contains a malformed SHA-256 digest.")
        actual_hash, actual_size = self._sha256(apk_path)
        if actual_hash != expected_hash:
            raise DecompilationError(
                f"APK SHA-256 changed after acquisition: expected {expected_hash}, "
                f"received {actual_hash}."
            )
        expected_size = int(row.get("size") or 0)
        if expected_size and actual_size != expected_size:
            raise DecompilationError(
                f"APK size changed after acquisition: expected {expected_size}, "
                f"received {actual_size}."
            )
        return apk_path

    @staticmethod
    def _log_tail(log_path: Path, limit: int = 2000) -> str:
        """Read a bounded tail of a tool log for concise failure reporting."""
        try:
            with log_path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - limit))
                return handle.read(limit).decode("utf-8", errors="replace").strip()
        except OSError:
            return "(log unavailable)"

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
        """Terminate the subprocess session, including descendants, after timeout."""
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass

    def _run_tool(
        self,
        command: list[str],
        log_path: Path,
        label: str,
        *,
        accepted_return_codes: tuple[int, ...] = (0,),
    ) -> int:
        """Stream combined tool output to disk and bound execution time."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            log_fd = os.open(log_path, flags, 0o600)
            os.fchmod(log_fd, 0o600)
            with os.fdopen(log_fd, "wb") as log_file:
                log_file.write(
                    f"COMMAND: {' '.join(command)}\nSTDOUT AND STDERR (combined):\n".encode(
                        "utf-8", errors="replace"
                    )
                )
                log_file.flush()
                log_offset = log_file.tell()
                process = subprocess.Popen(
                    command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                stop_tailer = threading.Event()
                tailer = None
                if self.progress is not None:
                    def stream_log() -> None:
                        pending = b""
                        started = time.monotonic()
                        last_heartbeat = started
                        try:
                            with log_path.open("rb") as reader:
                                reader.seek(log_offset)
                                while not stop_tailer.is_set():
                                    chunk = reader.read(64 * 1024)
                                    if chunk:
                                        pending += chunk
                                        while b"\n" in pending:
                                            raw_line, pending = pending.split(b"\n", 1)
                                            try:
                                                self.progress(raw_line.decode("utf-8", errors="replace"))
                                            except Exception:  # progress UI must not interrupt evidence collection
                                                pass
                                    else:
                                        stop_tailer.wait(0.15)
                                        now = time.monotonic()
                                        if now - last_heartbeat >= 1.0 and not stop_tailer.is_set():
                                            try:
                                                self.progress(
                                                    f"[{label}] still running — "
                                                    f"{int(now - started)}s elapsed"
                                                )
                                            except Exception:
                                                pass
                                            last_heartbeat = now
                                while True:
                                    chunk = reader.read(64 * 1024)
                                    if not chunk:
                                        break
                                    pending += chunk
                                    while b"\n" in pending:
                                        raw_line, pending = pending.split(b"\n", 1)
                                        try:
                                            self.progress(raw_line.decode("utf-8", errors="replace"))
                                        except Exception:
                                            pass
                                if pending:
                                    try:
                                        self.progress(pending.decode("utf-8", errors="replace"))
                                    except Exception:
                                        pass
                        except OSError as exc:
                            try:
                                self.progress(f"[{label}] live log stream unavailable: {exc}")
                            except Exception:
                                pass
                    tailer = threading.Thread(target=stream_log, name="apkworkbench-log-tail", daemon=True)
                    tailer.start()
                previous_sigterm = None

                def handle_sigterm(signum, _frame):
                    raise KeyboardInterrupt(f"received signal {signum}")

                try:
                    try:
                        previous_sigterm = signal.signal(signal.SIGTERM, handle_sigterm)
                    except ValueError:
                        # Signal handlers can only be installed from the main thread.
                        pass
                    returncode = process.wait(timeout=self.timeout_seconds)
                except subprocess.TimeoutExpired:
                    self._terminate_process_tree(process)
                    log_file.write(
                        f"\nTIMEOUT AFTER: {self.timeout_seconds} seconds\n".encode(
                            "utf-8", errors="replace"
                        )
                    )
                    log_file.flush()
                    raise DecompilationError(
                        f"{label} exceeded the {self.timeout_seconds}-second timeout. "
                        f"See log: {log_path}"
                    ) from None
                except KeyboardInterrupt:
                    self._terminate_process_tree(process)
                    log_file.write(b"\nINTERRUPTED: process group terminated\n")
                    log_file.flush()
                    raise
                finally:
                    stop_tailer.set()
                    if tailer is not None:
                        tailer.join(timeout=2)
                    if previous_sigterm is not None:
                        signal.signal(signal.SIGTERM, previous_sigterm)
                log_file.write(
                    f"\nRETURN CODE: {returncode}\n".encode("utf-8", errors="replace")
                )
        except FileNotFoundError as exc:
            raise DecompilationError(
                f"Required executable was not found: {command[0]}"
            ) from exc
        except OSError as exc:
            raise DecompilationError(f"Could not execute {label}: {exc}") from exc

        if returncode not in accepted_return_codes:
            detail = self._log_tail(log_path)
            raise DecompilationError(
                f"{label} exited with status {returncode}. {detail}"
            )
        return returncode

    @staticmethod
    def _has_usable_output(path: Path) -> bool:
        """Return true only for a real directory containing at least one file."""
        if path.is_symlink() or not path.is_dir():
            return False
        try:
            return any(
                item.is_file() and not item.is_symlink()
                for item in path.rglob("*")
            )
        except OSError:
            return False

    @staticmethod
    def _remove_existing_output(path: Path) -> None:
        """Remove a staging/backup path without following symlinks."""
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)

    def _publish_output(self, staged: Path, destination: Path, label: str) -> None:
        """Replace a tool output only after its staged replacement has validated."""
        if not self._has_usable_output(staged):
            raise DecompilationError(
                f"{label} exited successfully but produced no usable output; "
                "the previous output was retained."
            )

        backup = destination.with_name(
            f".{destination.name}.previous-{uuid.uuid4().hex}"
        )
        moved_previous = False
        try:
            if destination.exists() or destination.is_symlink():
                os.replace(destination, backup)
                moved_previous = True
            os.replace(staged, destination)
        except OSError as exc:
            if moved_previous:
                try:
                    os.replace(backup, destination)
                except OSError as rollback_exc:
                    raise DecompilationError(
                        f"Could not publish {label} output ({exc}) or restore its "
                        f"previous output ({rollback_exc}); backup retained at {backup}."
                    ) from exc
            raise DecompilationError(
                f"Could not publish {label} output: {exc}"
            ) from exc

        if moved_previous:
            try:
                self._remove_existing_output(backup)
            except OSError as exc:
                self.logger.warning(
                    "Published new %s output but could not remove previous backup %s: %s",
                    label,
                    backup,
                    exc,
                )

    def _run_tool_transactionally(
        self,
        command: list[str],
        *,
        staged_output: Path,
        destination: Path,
        log_path: Path,
        label: str,
        allow_partial: bool = False,
    ) -> str:
        """Run into a temporary sibling and publish only usable, validated output.

        With allow_partial enabled, non-zero exits or terminated processes may still
        publish useful decoded files. Such output is explicitly marked partial.
        Empty staging output remains a hard failure.
        """
        try:
            staged_output.mkdir(mode=0o700)
            accepted_codes = tuple(range(-255, 256)) if allow_partial else (0,)
            try:
                returncode = self._run_tool(
                    command,
                    log_path,
                    label,
                    accepted_return_codes=accepted_codes,
                )
            except DecompilationError:
                if not allow_partial or not self._has_usable_output(staged_output):
                    raise
                self.logger.warning(
                    "%s was interrupted or exited abnormally after writing usable output; "
                    "publishing it as partial for downstream scanning. See %s",
                    label,
                    log_path,
                )
                self._publish_output(staged_output, destination, label)
                return "partial"

            if returncode != 0:
                if not allow_partial or not self._has_usable_output(staged_output):
                    detail = self._log_tail(log_path)
                    raise DecompilationError(
                        f"{label} exited with status {returncode} and produced no usable output. "
                        f"{detail}"
                    )
                self.logger.warning(
                    "%s exited with status %s after writing usable output; "
                    "publishing it as partial for downstream scanning. See %s",
                    label,
                    returncode,
                    log_path,
                )
                self._publish_output(staged_output, destination, label)
                return "partial"

            self._publish_output(staged_output, destination, label)
            return "success"
        except OSError as exc:
            raise DecompilationError(
                f"Could not prepare or clean up staged {label} output: {exc}"
            ) from exc
        finally:
            if staged_output.exists() or staged_output.is_symlink():
                try:
                    self._remove_existing_output(staged_output)
                except OSError as exc:
                    self.logger.warning(
                        "Could not remove incomplete %s staging output %s: %s",
                        label,
                        staged_output,
                        exc,
                    )

    def _status_update(
        self,
        row: dict[str, str],
        *,
        apktool_status: str,
        scan_status: str,
        error: str = "",
    ) -> None:
        # Retain the legacy CSV column so existing workspaces remain readable.
        # New runs no longer invoke JADX.
        self.database.update_processing_status(
            {
                "sha256": row["sha256"],
                "package_id": row.get("package_id", ""),
                "version_code": row.get("version_code", ""),
                "jadx_status": "not_used",
                "apktool_status": apktool_status,
                "scan_status": scan_status,
                "updated_at": utc_now(),
                "error": error[:2000],
            }
        )

    def _validate_workspace_roots(self) -> None:
        for label, root in (
            ("downloads", self.download_root),
            ("results", self.results_root),
        ):
            root.mkdir(parents=True, exist_ok=True)
            try:
                root.resolve(strict=True).relative_to(self.workspace)
            except (OSError, ValueError) as exc:
                raise DecompilationError(
                    f"The {label} directory resolves outside the configured workspace."
                ) from exc
        self.download_root = self.download_root.resolve(strict=True)
        self.results_root = self.results_root.resolve(strict=True)

    def run(
        self,
        *,
        limit: int | None = None,
        force: bool = False,
        run_id: str | None = None,
    ) -> DecompilationSummary:
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1 when supplied")
        self._validate_workspace_roots()
        self.database.ensure()
        history = self.database.read_download_history()
        statuses = self.database.read_processing_status()
        examined = completed = failed = skipped = partial = 0

        if run_id is None:
            candidate_rows = history
        else:
            manifest_rows = self.database.read_manifest(run_id)
            if any(row.get("source") not in {"google_play", "fdroid"} for row in manifest_rows):
                raise DecompilationError(
                    "Refusing to process a manifest with an unsupported acquisition source."
                )
            history_by_hash = {
                row.get("sha256", "").lower(): row for row in history if row.get("sha256")
            }
            candidate_rows = []
            for selected in manifest_rows:
                acquired = history_by_hash.get(selected["sha256"])
                if (
                    acquired is None
                    or acquired.get("source") != selected.get("source")
                    or acquired.get("run_id") != run_id
                    or acquired.get("package_id") != selected.get("package_id")
                    or str(acquired.get("version_code", "")) != str(selected.get("version_code", ""))
                ):
                    skipped += 1
                    continue
                candidate_rows.append(acquired)

        total_candidates = len(candidate_rows)
        for item_index, row in enumerate(candidate_rows, start=1):
            digest = row.get("sha256", "").lower()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                failed += 1
                self.logger.error(
                    "Acquisition history contains an invalid SHA-256; item cannot be processed."
                )
                continue

            previous = statuses.get(digest, {})
            scan_status = previous.get("scan_status") or "pending"
            package_id = row.get("package_id", "unknown")
            version_code = str(row.get("version_code", "unknown"))

            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                self._status_update(
                    row,
                    apktool_status="failed",
                    scan_status=scan_status,
                    error=f"Unsafe package ID in download history: {package_id!r}",
                )
                failed += 1
                continue
            if not version_code.isdigit():
                self._status_update(
                    row,
                    apktool_status="failed",
                    scan_status=scan_status,
                    error=f"Unsafe version code in download history: {version_code!r}",
                )
                failed += 1
                continue

            package_root = self.results_root / package_id
            version_root = package_root / version_code
            output_root = version_root / digest
            if any(path.is_symlink() for path in (package_root, version_root, output_root)):
                raise DecompilationError(
                    "Decompilation output path contains a symlinked workspace component."
                )
            try:
                output_root.resolve().relative_to(self.results_root.resolve())
            except ValueError as exc:
                raise DecompilationError(
                    "Resolved decompilation path escapes results workspace."
                ) from exc

            apktool_output = output_root / "apktool"
            output_root.mkdir(parents=True, exist_ok=True)

            # Verify the acquired APK on every pass, including when existing output
            # would otherwise be reused. A stale Apktool result must not bypass
            # verification of the source APK against its recorded SHA-256.
            try:
                apk_path = self._validated_apk_path(row)
            except (DecompilationError, OSError, ValueError) as exc:
                self._status_update(
                    row,
                    apktool_status="failed",
                    scan_status=scan_status,
                    error=str(exc),
                )
                failed += 1
                continue

            # Ignore historical JADX status. Reuse Apktool only after the source
            # APK has passed SHA-256 and size verification.
            apktool_had_usable_output = (
                previous.get("apktool_status") in {"success", "partial"}
                and self._has_usable_output(apktool_output)
            )
            if not force and apktool_had_usable_output:
                self._status_update(
                    row,
                    apktool_status=previous.get("apktool_status", "success"),
                    scan_status=scan_status,
                )
                skipped += 1
                continue

            if limit is not None and examined >= limit:
                break
            examined += 1

            if self.progress is not None:
                self.progress(f"[Apktool {item_index}/{total_candidates}] {package_id} v{version_code}: SHA-256 verified; starting decode")
            self._status_update(
                row,
                apktool_status="running",
                scan_status=scan_status,
            )
            staged_output = apktool_output.with_name(
                f".{apktool_output.name}.staging-{uuid.uuid4().hex}"
            )
            command = [
                self.apktool_executable,
                "d",
                "--jobs",
                "4",
                "--force",
                "-o",
                str(staged_output),
                str(apk_path),
            ]

            errors: list[str] = []
            try:
                stage_status = self._run_tool_transactionally(
                    command,
                    staged_output=staged_output,
                    destination=apktool_output,
                    log_path=output_root / "apktool.log",
                    label="Apktool",
                    allow_partial=True,
                )
            except (DecompilationError, OSError) as exc:
                errors.append(str(exc))
                # A failed forced refresh never destroys previous usable output.
                stage_status = previous.get("apktool_status", "success") if apktool_had_usable_output else "failed"

            if stage_status == "partial" and not errors:
                errors.append(
                    "Apktool produced usable partial output after a non-zero exit or interruption; "
                    "the saved output is eligible for TruffleHog. "
                    f"See {output_root / 'apktool.log'}"
                )
            self._status_update(
                row,
                apktool_status=stage_status,
                scan_status=scan_status,
                error="; ".join(errors),
            )
            if stage_status == "success" and not errors:
                completed += 1
                self.logger.info("Apktool decoding completed for %s", package_id)
                if self.progress is not None:
                    self.progress(f"[Apktool {item_index}/{total_candidates}] COMPLETE: {package_id}")
            elif stage_status == "partial":
                partial += 1
                self.logger.warning(
                    "Apktool produced partial but usable output for %s: %s",
                    package_id,
                    "; ".join(errors),
                )
            else:
                failed += 1
                self.logger.error(
                    "Apktool decoding requires attention for %s: %s",
                    package_id,
                    "; ".join(errors) or "usable Apktool output is unavailable",
                )

        return DecompilationSummary(examined, completed, failed, skipped, partial)
