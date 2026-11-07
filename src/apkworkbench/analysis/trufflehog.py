"""Sequential local TruffleHog scanning with verification explicitly disabled."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import selectors
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
        # Kong presents boolean flags as --[no-]flag; normalize that notation.
        normalized_help = help_text.replace("[no-]", "")
        missing = [flag for flag in self.REQUIRED_HELP_FLAGS if flag not in normalized_help]
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
    def _sanitize_finding(item: dict[str, Any]) -> dict[str, Any] | None:
        detector = item.get("DetectorName")
        if not isinstance(detector, str) or not detector:
            return None
        canonical = json.dumps(
            item,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="replace")
        file_path, line_number = TruffleHogScanner._filesystem_metadata(item)
        return {
            "fingerprint": hashlib.sha256(canonical).hexdigest(),
            "detector_name": detector,
            "detector_type": item.get("DetectorType"),
            "decoder_name": item.get("DecoderName"),
            "file_path": file_path,
            "line": line_number,
            "verification": "disabled",
        }

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
            raise AnalysisError(f"Cannot publish sanitized scan results: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def _run_one(
        self, package_id: str, version_code: str, digest: str, directories: list[Path]
    ) -> list[dict[str, Any]]:
        self._check_cli_support()
        for directory in directories:
            try:
                directory.resolve(strict=True).relative_to(self.results_root.resolve())
            except (OSError, ValueError) as exc:
                raise AnalysisError(
                    f"Refusing to scan a decompilation directory outside results/: {directory}"
                ) from exc
            if not directory.is_dir():
                raise AnalysisError(f"Decompiled input directory is missing: {directory}")

        command = [
            self.executable,
            "filesystem",
            "--concurrency=1",
            "--no-update",
            "--no-verification",
            "--json",
            "--fail-on-scan-errors",
            *(str(path) for path in directories),
        ]
        findings: list[dict[str, Any]] = []
        fingerprints: set[str] = set()
        parse_error = False
        with tempfile.TemporaryFile(mode="w+b") as stdout_file:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    bufsize=0,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise AnalysisError(f"Could not start TruffleHog: {exc}") from exc

            if process.stdout is None:
                process.kill()
                process.wait()
                raise AnalysisError("TruffleHog stdout pipe was not created.")

            output_size = 0
            deadline = time.monotonic() + self.timeout_seconds
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            process.kill()
                            process.wait()
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
                                process.kill()
                                process.wait()
                                raise AnalysisError(
                                    "TruffleHog JSON output exceeded the configured "
                                    f"{self.max_output_bytes}-byte limit."
                                )
                            stdout_file.write(chunk)
                        else:
                            continue
                        break
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise AnalysisError(
                    f"TruffleHog exceeded the {self.timeout_seconds}-second timeout."
                ) from exc
            finally:
                process.stdout.close()

            stdout_file.flush()
            stdout_file.seek(0)
            max_line_bytes = 2 * 1024 * 1024
            while True:
                raw_line = stdout_file.readline(max_line_bytes + 1)
                if not raw_line:
                    break
                if len(raw_line) > max_line_bytes:
                    parse_error = True
                    while raw_line and not raw_line.endswith(b"\\n"):
                        raw_line = stdout_file.readline(64 * 1024)
                    continue
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
                finding = self._sanitize_finding(item)
                if finding is None or finding["fingerprint"] in fingerprints:
                    continue
                fingerprints.add(finding["fingerprint"])
                findings.append(finding)

        if parse_error:
            raise AnalysisError("TruffleHog emitted malformed or oversized JSON output; results were not published.")
        if return_code != 0:
            raise AnalysisError(
                f"TruffleHog exited with status {return_code}; results were not published."
            )

        output_dir = self.results_root / package_id / version_code / digest / "trufflehog"
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            output_dir.resolve(strict=True).relative_to(self.results_root.resolve())
            if any(part.is_symlink() for part in (
                self.results_root / package_id,
                self.results_root / package_id / version_code,
                self.results_root / package_id / version_code / digest,
                output_dir,
            )):
                raise ValueError("symlinked output component")
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
            "fingerprint",
            "detector_name",
            "detector_type",
            "decoder_name",
            "file_path",
            "line",
            "verification",
        ]
        rows: list[dict[str, object]] = []
        processing = self.database.read_processing_status()
        eligible_hashes = {
            digest
            for digest, row in processing.items()
            if row.get("scan_status") == "success"
        }
        for path in sorted(self.results_root.glob("*/*/*/trufflehog/findings.json")):
            try:
                path.resolve(strict=True).relative_to(self.results_root.resolve())
                digest = path.parents[1].name
                package_id = path.parents[3].name
                version_code = path.parents[2].name
                if digest not in eligible_hashes:
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
                            **{field: finding.get(field, "") for field in fields if field not in {"package_id", "version_code", "sha256"}},
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

    def run(self, *, limit: int | None = None, force: bool = False) -> AnalysisSummary:
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1 when supplied")
        self._validate_results_root()
        self.database.ensure()
        history = self.database.read_download_history()
        statuses = self.database.read_processing_status()
        scanned = findings_count = failed = skipped = 0

        for row in history:
            digest = row.get("sha256", "").lower()
            if not digest:
                continue
            previous = statuses.get(digest, {})
            if previous.get("jadx_status") != "success" or previous.get("apktool_status") != "success":
                skipped += 1
                continue
            if not force and previous.get("scan_status") == "success":
                skipped += 1
                continue
            if limit is not None and scanned + failed >= limit:
                break

            package_id = row.get("package_id", "")
            version_code = row.get("version_code", "")
            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+", package_id):
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
            self.logger.info(
                "TruffleHog found %d candidates in %s", len(findings), package_id
            )

        self._write_aggregate_csv()
        return AnalysisSummary(scanned, findings_count, failed, skipped)
