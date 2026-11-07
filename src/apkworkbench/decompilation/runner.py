"""Sequential JADX and Apktool execution for verified local APKs."""
from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
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


class DecompilationRunner:
    """Re-verify each acquired APK and run both decompilers sequentially."""

    def __init__(
        self,
        database: WorkspaceDatabase,
        *,
        workspace: str | Path,
        jadx_executable: str = "jadx",
        apktool_executable: str = "apktool",
        timeout_seconds: int = 3600,
        logger: logging.Logger | None = None,
    ):
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.database = database
        self.workspace = Path(workspace).expanduser().resolve()
        self.download_root = self.workspace / "downloads"
        self.results_root = self.workspace / "results"
        self.jadx_executable = jadx_executable
        self.apktool_executable = apktool_executable
        self.timeout_seconds = timeout_seconds
        self.logger = logger or logging.getLogger("apkworkbench.decompilation")

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
        apk_path = Path(raw_path).expanduser().resolve(strict=True)
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
        """Read only a bounded tail of a tool log for concise failure reporting."""
        with log_path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read(limit).decode("utf-8", errors="replace").strip()

    def _run_tool(self, command: list[str], log_path: Path, label: str) -> None:
        """Run a tool with output streamed to disk rather than buffered in memory."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with log_path.open("wb") as log_file:
                log_file.write(
                    (f"COMMAND: {' '.join(command)}\n"
                     "STDOUT AND STDERR (combined):\n").encode("utf-8", errors="replace")
                )
                log_file.flush()
                result = subprocess.run(
                    command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                log_file.write(f"\nRETURN CODE: {result.returncode}\n".encode("ascii"))
        except subprocess.TimeoutExpired as exc:
            try:
                with log_path.open("ab") as log_file:
                    log_file.write(
                        f"\nTIMEOUT AFTER: {self.timeout_seconds} seconds\n".encode("ascii")
                    )
            except OSError:
                pass
            raise DecompilationError(
                f"{label} exceeded the {self.timeout_seconds}-second timeout. "
                f"See log: {log_path}"
            ) from exc
        except FileNotFoundError as exc:
            raise DecompilationError(f"Required executable was not found: {command[0]}") from exc
        except OSError as exc:
            raise DecompilationError(f"Could not execute {label}: {exc}") from exc

        if result.returncode != 0:
            detail = self._log_tail(log_path)
            raise DecompilationError(
                f"{label} exited with status {result.returncode}. {detail}"
            )

    @staticmethod
    def _remove_existing_output(path: Path) -> None:
        """Remove an old tool output without following symlinks."""
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)

    def _status_update(
        self,
        row: dict[str, str],
        *,
        jadx_status: str,
        apktool_status: str,
        scan_status: str,
        error: str = "",
    ) -> None:
        self.database.update_processing_status(
            {
                "sha256": row["sha256"],
                "package_id": row.get("package_id", ""),
                "version_code": row.get("version_code", ""),
                "jadx_status": jadx_status,
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
        examined = completed = failed = skipped = 0

        if run_id is None:
            candidate_rows = history
        else:
            manifest_rows = self.database.read_manifest(run_id)
            history_by_hash = {
                row.get("sha256", "").lower(): row for row in history if row.get("sha256")
            }
            candidate_rows = []
            for selected in manifest_rows:
                acquired = history_by_hash.get(selected["sha256"])
                if (
                    acquired is None
                    or acquired.get("run_id") != run_id
                    or acquired.get("package_id") != selected.get("package_id")
                    or str(acquired.get("version_code", "")) != str(selected.get("version_code", ""))
                ):
                    # Failed downloads remain in the manifest but never become processing inputs.
                    skipped += 1
                    continue
                candidate_rows.append(acquired)

        for row in candidate_rows:
            digest = row.get("sha256", "").lower()
            if not digest:
                continue
            previous = statuses.get(digest, {})
            scan_status = previous.get("scan_status") or "pending"
            if (
                not force
                and previous.get("jadx_status") == "success"
                and previous.get("apktool_status") == "success"
            ):
                skipped += 1
                continue
            if limit is not None and examined >= limit:
                break
            examined += 1

            errors: list[str] = []
            try:
                apk_path = self._validated_apk_path(row)
            except (DecompilationError, OSError, ValueError) as exc:
                errors.append(str(exc))
                self._status_update(
                    row,
                    jadx_status="failed",
                    apktool_status="failed",
                    scan_status=scan_status,
                    error="; ".join(errors),
                )
                failed += 1
                continue

            package_id = row.get("package_id", "unknown")
            version_code = row.get("version_code", "unknown")
            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                errors.append(f"Unsafe package ID in download history: {package_id!r}")
                self._status_update(
                    row,
                    jadx_status="failed",
                    apktool_status="failed",
                    scan_status=scan_status,
                    error="; ".join(errors),
                )
                failed += 1
                continue
            if not version_code.isdigit():
                errors.append(f"Unsafe version code in download history: {version_code!r}")
                self._status_update(
                    row,
                    jadx_status="failed",
                    apktool_status="failed",
                    scan_status=scan_status,
                    error="; ".join(errors),
                )
                failed += 1
                continue

            output_root = self.results_root / package_id / version_code / digest
            try:
                output_root.resolve().relative_to(self.results_root.resolve())
            except ValueError as exc:
                raise DecompilationError("Resolved decompilation path escapes results workspace.") from exc
            jadx_output = output_root / "jadx"
            apktool_output = output_root / "apktool"
            output_root.mkdir(parents=True, exist_ok=True)

            self._status_update(
                row,
                jadx_status="running",
                apktool_status="pending",
                scan_status=scan_status,
            )
            self._remove_existing_output(jadx_output)
            jadx_command = [
                self.jadx_executable,
                "--threads-count",
                "1",
                "--output-dir",
                str(jadx_output),
                str(apk_path),
            ]
            try:
                self._run_tool(jadx_command, output_root / "jadx.log", "JADX")
                jadx_status = "success"
            except DecompilationError as exc:
                jadx_status = "failed"
                errors.append(str(exc))
            self._status_update(
                row,
                jadx_status=jadx_status,
                apktool_status="running",
                scan_status=scan_status,
                error="; ".join(errors),
            )

            self._remove_existing_output(apktool_output)
            apktool_command = [
                self.apktool_executable,
                "d",
                "--jobs",
                "1",
                "--force",
                "-o",
                str(apktool_output),
                str(apk_path),
            ]
            try:
                self._run_tool(apktool_command, output_root / "apktool.log", "Apktool")
                apktool_status = "success"
            except DecompilationError as exc:
                apktool_status = "failed"
                errors.append(str(exc))

            self._status_update(
                row,
                jadx_status=jadx_status,
                apktool_status=apktool_status,
                scan_status=scan_status,
                error="; ".join(errors),
            )
            if jadx_status == "success" and apktool_status == "success":
                completed += 1
                self.logger.info("Decompilation completed for %s", package_id)
            else:
                failed += 1
                self.logger.error(
                    "Decompilation failed for %s: %s", package_id, "; ".join(errors)
                )

        return DecompilationSummary(examined, completed, failed, skipped)
