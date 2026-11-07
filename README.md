"""Sequential JADX and Apktool execution for verified local APKs."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import signal
import subprocess
import uuid
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
                process = subprocess.Popen(
                    command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                previous_sigterm = None

                def handle_sigterm(signum, _frame):
                    raise KeyboardInterrupt(f"received signal {signum}")

                try:
                    try:
                        previous_sigterm = signal.signal(signal.SIGTERM, handle_sigterm)
                    except ValueError:
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
        """Run into a temporary sibling and publish only a validated result."""
        try:
            staged_output.mkdir(mode=0o700)
            returncode = self._run_tool(
                command,
                log_path,
                label,
                accepted_return_codes=(0, 3) if allow_partial else (0,),
            )
            if returncode == 3:
                if not self._has_usable_output(staged_output):
                    raise DecompilationError(
                        f"{label} exited with status 3 but produced no usable output."
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
        examined = completed = failed = skipped = partial = 0

        if run_id is None:
            candidate_rows = history
        else:
            manifest_rows = self.database.read_manifest(run_id)
            if any(row.get("source") not in {"google_play", "fdroid"} for row in manifest_rows):
                raise DecompilationError("Refusing to process a manifest with an unsupported acquisition source.")
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

        for row in candidate_rows:
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
            version_code = row.get("version_code", "unknown")
            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                self._status_update(
                    row,
                    jadx_status="failed",
                    apktool_status="failed",
                    scan_status=scan_status,
                    error=f"Unsafe package ID in download history: {package_id!r}",
                )
                failed += 1
                continue
            if not version_code.isdigit():
                self._status_update(
                    row,
                    jadx_status="failed",
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
            jadx_output = output_root / "jadx"
            apktool_output = output_root / "apktool"
            output_root.mkdir(parents=True, exist_ok=True)

            jadx_had_usable_output = (
                previous.get("jadx_status") in {"success", "partial"}
                and self._has_usable_output(jadx_output)
            )
            apktool_had_usable_output = (
                previous.get("apktool_status") == "success"
                and self._has_usable_output(apktool_output)
            )
            jadx_status = (
                previous.get("jadx_status", "success")
                if jadx_had_usable_output else "pending"
            )
            apktool_status = "success" if apktool_had_usable_output else "pending"
            jadx_existing_status = jadx_status
            apktool_existing_status = apktool_status

            if not force and jadx_had_usable_output and apktool_had_usable_output:
                skipped += 1
                if jadx_status == "partial":
                    partial += 1
                continue
            if limit is not None and examined >= limit:
                break
            examined += 1

            try:
                apk_path = self._validated_apk_path(row)
            except (DecompilationError, OSError, ValueError) as exc:
                self._status_update(
                    row,
                    jadx_status=jadx_status if jadx_had_usable_output else "failed",
                    apktool_status=apktool_status if apktool_had_usable_output else "failed",
                    scan_status=scan_status,
                    error=str(exc),
                )
                failed += 1
                continue

            errors: list[str] = []
            warnings: list[str] = []
            self._status_update(
                row,
                jadx_status=jadx_status,
                apktool_status=apktool_status,
                scan_status=scan_status,
            )

            stages = (
                (
                    "JADX",
                    self.jadx_executable,
                    jadx_output,
                    "jadx",
                    ["--threads-count", "4", "--output-dir"],
                ),
                (
                    "Apktool",
                    self.apktool_executable,
                    apktool_output,
                    "apktool",
                    ["d", "--jobs", "4", "--force", "-o"],
                ),
            )
            for label, executable, destination, tool_name, arguments in stages:
                current_status = jadx_status if tool_name == "jadx" else apktool_status
                if not force and current_status in {"success", "partial"}:
                    continue

                staged_output = destination.with_name(
                    f".{destination.name}.staging-{uuid.uuid4().hex}"
                )
                command = [executable, *arguments, str(staged_output), str(apk_path)]
                if tool_name == "jadx":
                    jadx_status = "running"
                else:
                    apktool_status = "running"
                self._status_update(
                    row,
                    jadx_status=jadx_status,
                    apktool_status=apktool_status,
                    scan_status=scan_status,
                    error="; ".join(errors + warnings),
                )

                try:
                    stage_status = self._run_tool_transactionally(
                        command,
                        staged_output=staged_output,
                        destination=destination,
                        log_path=output_root / f"{tool_name}.log",
                        label=label,
                        allow_partial=(tool_name == "jadx"),
                    )
                    if stage_status == "partial":
                        warnings.append(
                            "JADX completed with decompilation errors (exit code 3); "
                            "usable partial output was retained."
                        )
                except (DecompilationError, OSError) as exc:
                    errors.append(str(exc))
                    had_usable_output = (
                        jadx_had_usable_output if tool_name == "jadx"
                        else apktool_had_usable_output
                    )
                    existing_status = (
                        jadx_existing_status if tool_name == "jadx"
                        else apktool_existing_status
                    )
                    stage_status = existing_status if had_usable_output else "failed"

                if tool_name == "jadx":
                    jadx_status = stage_status
                else:
                    apktool_status = stage_status
                self._status_update(
                    row,
                    jadx_status=jadx_status,
                    apktool_status=apktool_status,
                    scan_status=scan_status,
                    error="; ".join(errors + warnings),
                )

            usable_statuses = {"success", "partial"}
            if jadx_status in usable_statuses and apktool_status in usable_statuses and not errors:
                if "partial" in {jadx_status, apktool_status}:
                    partial += 1
                    self.logger.warning(
                        "Decompilation completed with partial JADX output for %s: %s",
                        package_id,
                        "; ".join(warnings),
                    )
                else:
                    completed += 1
                    self.logger.info("Decompilation completed for %s", package_id)
            else:
                failed += 1
                self.logger.error(
                    "Decompilation requires attention for %s: %s",
                    package_id,
                    "; ".join(errors) or "one or more tool outputs are unavailable",
                )

        return DecompilationSummary(examined, completed, failed, skipped, partial)


"""Sequential local TruffleHog scanning with verification explicitly disabled."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import selectors
import signal
import subprocess
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..database.workspace import WorkspaceDatabase, utc_now


class AnalysisError(RuntimeError):
    """Raised when local secret scanning cannot run safely or completely."""


@dataclass(frozen=True)
class AnalysisSummary:
    scanned: int
    findings: int
    failed: int
    skipped: int
    finding_records: tuple[dict[str, Any], ...] = ()


class TruffleHogScanner:
    """Scan completed decompilations without active credential verification."""

    REQUIRED_HELP_FLAGS = (
        "--no-verification",
        "--no-update",
        "--json",
        "--concurrency",
        "--fail-on-scan-errors",
    )

    def __init__(
        self,
        database: WorkspaceDatabase,
        *,
        workspace: str | Path,
        executable: str = "trufflehog",
        timeout_seconds: int = 7200,
        max_output_bytes: int = 512 * 1024 * 1024,
        logger: logging.Logger | None = None,
    ):
        if timeout_seconds < 1 or max_output_bytes < 1:
            raise ValueError("timeout_seconds and max_output_bytes must be positive")
        self.database = database
        self.workspace = Path(workspace).expanduser().resolve()
        self.results_root = self.workspace / "results"
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.logger = logger or logging.getLogger("apkworkbench.analysis")
        self._help_checked = False

    def _check_cli_support(self) -> None:
        if self._help_checked:
            return
        try:
            result = subprocess.run(
                [self.executable, "filesystem", "--help"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AnalysisError(f"Unable to inspect TruffleHog CLI capabilities: {exc}") from exc
        help_text = (result.stdout or "") + "\n" + (result.stderr or "")

        def supported(flag: str) -> bool:
            if flag in help_text:
                return True
            return flag.startswith("--") and f"--[no-]{flag[2:]}" in help_text

        missing = [flag for flag in self.REQUIRED_HELP_FLAGS if not supported(flag)]
        if missing:
            raise AnalysisError(
                "Installed TruffleHog filesystem command does not advertise required safe "
                "flags: " + ", ".join(missing) + ". No scan was started."
            )
        self._help_checked = True

    @staticmethod
    def _filesystem_metadata(item: dict[str, Any]) -> tuple[str, int | None]:
        source = item.get("SourceMetadata")
        if not isinstance(source, dict):
            return "", None
        data = source.get("Data")
        if not isinstance(data, dict):
            return "", None
        filesystem = data.get("Filesystem") or data.get("filesystem")
        if not isinstance(filesystem, dict):
            return "", None
        file_path = filesystem.get("file") or filesystem.get("File") or ""
        line = filesystem.get("line") or filesystem.get("Line")
        try:
            line_number = int(line) if line is not None else None
        except (TypeError, ValueError):
            line_number = None
        return str(file_path), line_number

    @staticmethod
    def _finding_fingerprint(item: dict[str, Any]) -> str:
        canonical = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _atomic_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
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
            raise AnalysisError(f"Cannot publish complete scan results: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
        """Terminate TruffleHog and any descendants in its dedicated process group."""
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

    @staticmethod
    def _stderr_tail(handle, limit: int = 8192) -> str:
        handle.flush()
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - limit))
        return handle.read(limit).decode("utf-8", errors="replace").strip()

    def _run_one(
        self, package_id: str, version_code: str, digest: str, directories: list[Path]
    ) -> list[dict[str, Any]]:
        self._check_cli_support()
        for directory in directories:
            relative = directory.relative_to(self.results_root)
            components = [self.results_root / part for part in relative.parts]
            if any(component.is_symlink() for component in components):
                raise AnalysisError(
                    f"Refusing to scan a symlinked decompilation path component: {directory}"
                )
            try:
                directory.resolve(strict=True).relative_to(self.results_root.resolve())
            except (OSError, ValueError) as exc:
                raise AnalysisError(
                    f"Refusing to scan a decompilation directory outside results/: {directory}"
                ) from exc
            if not directory.is_dir():
                raise AnalysisError(f"Decompiled input directory is missing or unsafe: {directory}")
            has_usable_file = False
            try:
                for item in directory.rglob("*"):
                    if item.is_symlink():
                        raise AnalysisError(
                            f"Refusing to scan a symlink inside decompilation output: {item}"
                        )
                    if item.is_file():
                        has_usable_file = True
            except OSError as exc:
                raise AnalysisError(
                    f"Cannot inspect decompilation input directory: {directory}: {exc}"
                ) from exc
            if not has_usable_file:
                raise AnalysisError(
                    f"Decompiled input directory contains no usable files: {directory}"
                )

        command = [
            self.executable,
            "filesystem",
            "--concurrency=4",
            "--no-update",
            "--no-verification",
            "--json",
            "--fail-on-scan-errors",
            *(str(path) for path in directories),
        ]
        findings: list[dict[str, Any]] = []
        parse_error = False
        with (
            tempfile.TemporaryFile(mode="w+b") as stdout_file,
            tempfile.TemporaryFile(mode="w+b") as stderr_file,
        ):
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=stderr_file,
                    bufsize=0,
                    start_new_session=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise AnalysisError(f"Could not start TruffleHog: {exc}") from exc

            if process.stdout is None:
                self._terminate_process_tree(process)
                raise AnalysisError("TruffleHog stdout pipe was not created.")

            output_size = 0
            deadline = time.monotonic() + self.timeout_seconds
            previous_sigterm = None

            def handle_sigterm(signum, _frame):
                raise KeyboardInterrupt(f"received signal {signum}")

            try:
                try:
                    previous_sigterm = signal.signal(signal.SIGTERM, handle_sigterm)
                except ValueError:
                    pass
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self._terminate_process_tree(process)
                            raise AnalysisError(
                                f"TruffleHog exceeded the {self.timeout_seconds}-second timeout."
                            )
                        events = selector.select(timeout=min(remaining, 0.25))
                        if not events:
                            continue
                        for _key, _mask in events:
                            chunk = os.read(process.stdout.fileno(), 64 * 1024)
                            if not chunk:
                                selector.unregister(process.stdout)
                                return_code = process.wait(
                                    timeout=max(0.01, deadline - time.monotonic())
                                )
                                break
                            output_size += len(chunk)
                            if output_size > self.max_output_bytes:
                                self._terminate_process_tree(process)
                                raise AnalysisError(
                                    "TruffleHog JSON output exceeded the configured "
                                    f"{self.max_output_bytes}-byte limit."
                                )
                            stdout_file.write(chunk)
                        else:
                            continue
                        break
            except subprocess.TimeoutExpired as exc:
                self._terminate_process_tree(process)
                raise AnalysisError(
                    f"TruffleHog exceeded the {self.timeout_seconds}-second timeout."
                ) from exc
            except KeyboardInterrupt:
                self._terminate_process_tree(process)
                raise
            finally:
                process.stdout.close()
                if previous_sigterm is not None:
                    signal.signal(signal.SIGTERM, previous_sigterm)

            stderr_tail = self._stderr_tail(stderr_file)
            stdout_file.flush()
            stdout_file.seek(0)
            while True:
                raw_line = stdout_file.readline()
                if not raw_line:
                    break
                if not raw_line.strip():
                    continue
                try:
                    item = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parse_error = True
                    continue
                if not isinstance(item, dict):
                    parse_error = True
                    continue
                findings.append(item)

        if parse_error:
            detail = f" Stderr: {stderr_tail[-2000:]}" if stderr_tail else ""
            raise AnalysisError(
                "TruffleHog emitted malformed or oversized JSON output; results were not "
                f"published.{detail}"
            )
        if return_code != 0:
            detail = f" Stderr: {stderr_tail[-2000:]}" if stderr_tail else ""
            raise AnalysisError(
                f"TruffleHog exited with status {return_code}; results were not published."
                f"{detail}"
            )

        output_dir = self.results_root / package_id / version_code / digest / "trufflehog"
        output_components = (
            self.results_root / package_id,
            self.results_root / package_id / version_code,
            self.results_root / package_id / version_code / digest,
            output_dir,
        )
        try:
            if any(part.is_symlink() for part in output_components):
                raise ValueError("symlinked output component")
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.resolve(strict=True).relative_to(self.results_root.resolve())
        except (OSError, ValueError) as exc:
            raise AnalysisError(
                f"TruffleHog output path escapes or aliases the results workspace: {output_dir}"
            ) from exc
        self._atomic_json(output_dir / "findings.json", findings)
        log_text = (
            f"COMMAND: {' '.join(command)}\n"
            f"RETURN CODE: {return_code}\n"
            f"FINDINGS: {len(findings)}\n"
            "CREDENTIAL VERIFICATION: DISABLED (--no-verification)\n"
        )
        (output_dir / "trufflehog.log").write_text(log_text, encoding="utf-8")
        return findings

    def _has_usable_scan_output(
        self, package_id: str, version_code: str, digest: str
    ) -> bool:
        output_dir = (
            self.results_root / package_id / version_code / digest / "trufflehog"
        )
        findings_path = output_dir / "findings.json"
        components = (
            self.results_root / package_id,
            self.results_root / package_id / version_code,
            self.results_root / package_id / version_code / digest,
            output_dir,
            findings_path,
        )
        if any(path.is_symlink() for path in components):
            return False
        try:
            findings_path.resolve(strict=True).relative_to(self.results_root.resolve(strict=True))
            if not findings_path.is_file():
                return False
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return False
        return isinstance(findings, list) and all(
            isinstance(item, dict) for item in findings
        )

    def _update_status(self, row: dict[str, str], status: str, error: str = "") -> None:
        self.database.update_processing_status(
            {
                "sha256": row["sha256"],
                "package_id": row.get("package_id", ""),
                "version_code": row.get("version_code", ""),
                "scan_status": status,
                "updated_at": utc_now(),
                "error": error[:2000],
            }
        )

    def _write_aggregate_csv(self) -> None:
        report_dir = self.workspace / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        destination = report_dir / "findings.csv"
        fields = [
            "package_id",
            "version_code",
            "sha256",
            "detector_name",
            "detector_type",
            "decoder_name",
            "file_path",
            "line",
            "verification",
            "finding_json",
        ]
        rows: list[dict[str, object]] = []
        processing = self.database.read_processing_status()
        eligible_hashes = {
            digest
            for digest, row in processing.items()
            if row.get("scan_status") == "success"
        }
        acquired_hashes = {
            row.get("sha256", "").lower()
            for row in self.database.read_download_history()
        }
        for path in sorted(self.results_root.glob("*/*/*/trufflehog/findings.json")):
            try:
                path.resolve(strict=True).relative_to(self.results_root.resolve())
                digest = path.parents[1].name
                package_id = path.parents[3].name
                version_code = path.parents[2].name
                if digest not in eligible_hashes or digest not in acquired_hashes:
                    continue
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(loaded, list):
                continue
            for finding in loaded:
                if isinstance(finding, dict):
                    rows.append(
                        {
                            "package_id": package_id,
                            "version_code": version_code,
                            "sha256": digest,
                            "detector_name": finding.get("DetectorName", ""),
                            "detector_type": finding.get("DetectorType", ""),
                            "decoder_name": finding.get("DecoderName", ""),
                            "file_path": self._filesystem_metadata(finding)[0],
                            "line": self._filesystem_metadata(finding)[1],
                            "verification": "disabled",
                            "finding_json": json.dumps(finding, ensure_ascii=False, separators=(",", ":")),
                        }
                    )

        fd, temporary_name = tempfile.mkstemp(
            prefix=".findings.", suffix=".tmp", dir=report_dir
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        except OSError as exc:
            raise AnalysisError(f"Cannot update aggregate findings CSV: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def _validate_results_root(self) -> None:
        self.results_root.mkdir(parents=True, exist_ok=True)
        try:
            self.results_root.resolve(strict=True).relative_to(self.workspace)
        except (OSError, ValueError) as exc:
            raise AnalysisError(
                "Results directory resolves outside the configured workspace."
            ) from exc
        self.results_root = self.results_root.resolve(strict=True)

    def run(
        self,
        *,
        limit: int | None = None,
        force: bool = False,
        run_id: str | None = None,
    ) -> AnalysisSummary:
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1 when supplied")
        self._validate_results_root()
        self.database.ensure()
        history = self.database.read_download_history()
        statuses = self.database.read_processing_status()
        scanned = findings_count = failed = skipped = 0
        finding_records: list[dict[str, Any]] = []

        if run_id is None:
            candidate_rows = history
        else:
            manifest_rows = self.database.read_manifest(run_id)
            if any(row.get("source") not in {"google_play", "fdroid"} for row in manifest_rows):
                raise AnalysisError("Refusing to scan a manifest with an unsupported acquisition source.")
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

        for row in candidate_rows:
            digest = row.get("sha256", "").lower()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                failed += 1
                self.logger.error(
                    "Acquisition history contains an invalid SHA-256; scan item cannot be processed."
                )
                continue
            previous = statuses.get(digest, {})
            if previous.get("jadx_status") not in {"success", "partial"} or previous.get("apktool_status") != "success":
                skipped += 1
                continue
            if (
                not force
                and previous.get("scan_status") == "success"
                and self._has_usable_scan_output(
                    row.get("package_id", ""),
                    row.get("version_code", ""),
                    digest,
                )
            ):
                skipped += 1
                continue
            if limit is not None and scanned + failed >= limit:
                break

            package_id = row.get("package_id", "")
            version_code = row.get("version_code", "")
            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                failed += 1
                self._update_status(row, "failed", f"Unsafe package ID: {package_id!r}")
                continue
            if not version_code.isdigit() or len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                failed += 1
                self._update_status(row, "failed", "Malformed version code or SHA-256 in history.")
                continue
            base_dir = self.results_root / package_id / version_code / digest
            directories = [base_dir / "jadx", base_dir / "apktool"]
            self._update_status(row, "running")
            try:
                findings = self._run_one(package_id, version_code, digest, directories)
            except AnalysisError as exc:
                failed += 1
                self._update_status(row, "failed", str(exc))
                self.logger.error("TruffleHog failed for %s: %s", package_id, exc)
                continue
            self._update_status(row, "success")
            scanned += 1
            findings_count += len(findings)
            finding_records.extend({"package_id": package_id, "version_code": version_code, "sha256": digest, "finding": item} for item in findings)
            self.logger.info(
                "TruffleHog found %d candidates in %s", len(findings), package_id
            )

        self._write_aggregate_csv()
        return AnalysisSummary(scanned, findings_count, failed, skipped, tuple(finding_records))


"""Regression tests for safe, retryable, bounded-memory decompilation."""
from __future__ import annotations

import csv
import hashlib
import logging
import signal
import subprocess
from pathlib import Path

import pytest

from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationError, DecompilationRunner


APK_BYTES = b"verified local apk fixture"


class FakeProcess:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.pid = 424242

    def wait(self, timeout=None):
        return self.returncode


def add_download(database: WorkspaceDatabase, workspace: Path, payload: bytes = APK_BYTES):
    digest = hashlib.sha256(payload).hexdigest()
    apk_path = workspace / "downloads/org.example.app/7" / digest / "app.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(payload)
    database.append_history(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": 7,
            "version_name": "7.0",
            "source": "google_play",
            "download_url": "google-play://fixture/app.apk",
            "local_path": str(apk_path),
            "size": len(payload),
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    return digest, apk_path


def output_path(command: list[str]) -> Path:
    flag = "--output-dir" if command[0] == "jadx" else "-o"
    return Path(command[command.index(flag) + 1])


def make_runner(workspace: Path):
    database = WorkspaceDatabase(workspace)
    database.ensure()
    digest, apk_path = add_download(database, workspace)
    runner = DecompilationRunner(
        database,
        workspace=workspace,
        jadx_executable="jadx",
        apktool_executable="apktool",
        timeout_seconds=30,
        logger=logging.getLogger("test-decompiler"),
    )
    return runner, database, digest, apk_path


def install_fake_popen(monkeypatch, behavior):
    calls = []

    def fake_popen(command, **kwargs):
        calls.append(command)
        assert kwargs["stderr"] == subprocess.STDOUT
        assert kwargs["start_new_session"] is True
        assert kwargs["stdout"] is not subprocess.PIPE
        behavior(command, kwargs)
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls


def successful_tool(command, kwargs, text="decompiled output"):
    kwargs["stdout"].write(f"{command[0]} output\n".encode())
    destination = output_path(command)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "fixture.txt").write_text(text, encoding="utf-8")


def test_runs_jadx_then_apktool_streaming_to_disk(monkeypatch, tmp_path):
    runner, database, digest, apk_path = make_runner(tmp_path)

    def behavior(command, kwargs):
        successful_tool(command, kwargs, command[0])

    calls = install_fake_popen(monkeypatch, behavior)
    summary = runner.run()

    assert summary.examined == summary.completed == 1
    assert summary.failed == 0
    assert [command[0] for command in calls] == ["jadx", "apktool"]
    assert calls[0][1:3] == ["--threads-count", "4"]
    assert calls[0][-1] == str(apk_path)
    assert calls[1][1:4] == ["d", "--jobs", "4"]
    state = database.read_processing_status()[digest]
    assert state["jadx_status"] == state["apktool_status"] == "success"
    assert state["scan_status"] == "pending"
    for name in ("jadx.log", "apktool.log"):
        log = (tmp_path / "results/org.example.app/7" / digest / name).read_bytes()
        assert b"STDOUT AND STDERR (combined)" in log
        assert b"output" in log
        assert b"RETURN CODE: 0" in log


"""Tests for complete TruffleHog result retention and safe execution."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import subprocess
import pytest
import shutil
from pathlib import Path

from apkworkbench.analysis.trufflehog import AnalysisError, TruffleHogScanner
from apkworkbench.database.workspace import WorkspaceDatabase


RAW_SECRET = "AKIAIOSFODNN7EXAMPLE"
HELP_TEXT = (
    "filesystem command help --no-verification --no-update --json "
    "--concurrency --fail-on-scan-errors"
)


class FakeProcess:
    def __init__(self, stdout, return_code: int = 0):
        self.stdout = stdout
        self.return_code = return_code
        self.killed = False
        self.pid = 424242

    def wait(self, timeout=None):
        return self.return_code

    def kill(self):
        self.killed = True


def result_json(raw=RAW_SECRET):
    return {
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "/workspace/results/org.example.app/7/jadx/sources/Config.java",
                    "line": 23,
                }
            }
        },
        "SourceID": 0,
        "SourceType": 15,
        "SourceName": "trufflehog - filesystem",
        "DetectorType": 2,
        "DetectorName": "AWS",
        "DecoderName": "PLAIN",
        "Verified": False,
        "Raw": raw,
        "RawV2": "secret-part",
        "Redacted": "AKIA...EXAMPLE",
        "ExtraData": {"account": "123456789012", "sensitive": "do-not-store"},
    }


def make_workspace(tmp_path: Path):
    database = WorkspaceDatabase(tmp_path)
    database.ensure()
    digest = hashlib.sha256(b"downloaded apk").hexdigest()
    apk = tmp_path / "downloads/org.example.app/7" / digest / "app.apk"
    apk.parent.mkdir(parents=True, exist_ok=True)
    apk.write_bytes(b"downloaded apk")
    database.append_history(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": 7,
            "version_name": "7.0",
            "source": "google_play",
            "download_url": "google-play://fixture/app.apk",
            "local_path": str(apk),
            "size": len(b"downloaded apk"),
            "run_id": "test-run",
            "downloaded_at": "2026-11-07T12:00:00+00:00",
            "index_sha256": "f" * 64,
        }
    )
    for tool in ("jadx", "apktool"):
        directory = tmp_path / "results/org.example.app/7" / digest / tool
        directory.mkdir(parents=True)
        (directory / "placeholder.txt").write_text("source code", encoding="utf-8")
    database.update_processing_status(
        {
            "sha256": digest,
            "package_id": "org.example.app",
            "version_code": "7",
            "jadx_status": "success",
            "apktool_status": "success",
            "scan_status": "pending",
            "error": "",
        }
    )
    return database, digest


def install_fakes(monkeypatch, output, *, return_code=0, help_text=HELP_TEXT, stderr=b""):
    calls = []
    read_fd, write_fd = os.pipe()
    if output:
        os.write(write_fd, output)
    os.close(write_fd)
    process = FakeProcess(os.fdopen(read_fd, "rb", buffering=0), return_code)

    def fake_run(command, **kwargs):
        calls.append(("help", command))
        return type(
            "Result",
            (),
            {"returncode": 0 if help_text else 1, "stdout": help_text, "stderr": ""},
        )()

    def fake_popen(command, **kwargs):
        calls.append(("scan", command))
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is not subprocess.DEVNULL
        assert kwargs["bufsize"] == 0
        assert kwargs["start_new_session"] is True
        kwargs["stderr"].write(stderr)
        return process

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls, process


def test_scanner_disables_verification_and_persists_complete_original_objects(monkeypatch, tmp_path):
    database, digest = make_workspace(tmp_path)
    line = json.dumps(result_json()).encode() + b"\n"
    calls, _ = install_fakes(monkeypatch, line)
    scanner = TruffleHogScanner(
        database,
        workspace=tmp_path,
        executable="trufflehog",
        logger=logging.getLogger("test-trufflehog"),
    )

    summary = scanner.run()

    assert summary.scanned == 1
    assert summary.findings == 1
    assert summary.failed == 0
    assert summary.finding_records == ({
        "package_id": "org.example.app",
        "version_code": "7",
        "sha256": digest,
        "finding": result_json(),
    },)
    command = next(entry[1] for entry in calls if entry[0] == "scan")
    assert command[0:2] == ["trufflehog", "filesystem"]
    assert "--no-verification" in command
    assert "--no-update" in command
    assert "--json" in command
    assert "--concurrency=4" in command
    assert "--fail-on-scan-errors" in command
    assert command[-2].endswith("/jadx")
    assert command[-1].endswith("/apktool")

    output = tmp_path / "results/org.example.app/7" / digest / "trufflehog/findings.json"
    records = json.loads(output.read_text(encoding="utf-8"))
    assert records == [result_json()]
    assert records[0]["Raw"] == RAW_SECRET
    assert records[0]["RawV2"] == "secret-part"
    assert records[0]["ExtraData"]["sensitive"] == "do-not-store"
    aggregate = (tmp_path / "reports/findings.csv").read_text(encoding="utf-8")
    assert RAW_SECRET in aggregate
    assert "finding_json" in aggregate
    assert database.read_processing_status()[digest]["scan_status"] == "success"


"""Keep the repository consistent and fast."""
}],