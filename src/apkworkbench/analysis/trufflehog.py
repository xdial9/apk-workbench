"""Sequential local TruffleHog scanning with verification explicitly disabled."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import subprocess
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
        logger: logging.Logger | None = None,
    ):
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.database = database
        self.workspace = Path(workspace).expanduser().resolve()
        self.results_root = self.workspace / "results"
        self.executable = executable
        self.timeout_seconds = timeout_seconds
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

    def _run_one(self, package_id: str, version_code: str, directories: list[Path]) -> list[dict[str, Any]]:
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
        process = None
        with tempfile.TemporaryFile(mode="w+b") as stderr_file:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=stderr_file,
                )
            except OSError as exc:
                raise AnalysisError(f"Could not start TruffleHog: {exc}") from exc

            if process.stdout is None:
                process.kill()
                process.wait()
                raise AnalysisError("TruffleHog stdout pipe was not created.")

            try:
                for raw_line in process.stdout:
                    if len(raw_line) > 2 * 1024 * 1024:
                        parse_error = True
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
                return_code = process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise AnalysisError(
                    f"TruffleHog exceeded the {self.timeout_seconds}-second timeout."
                ) from exc
            finally:
                process.stdout.close()

        if parse_error:
            raise AnalysisError("TruffleHog emitted malformed or oversized JSON output; results were not published.")
        if return_code != 0:
            raise AnalysisError(
                f"TruffleHog exited with status {return_code}; results were not published."
            )

        output_dir = self.results_root / package_id / version_code / "trufflehog"
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
            "fingerprint",
            "detector_name",
            "detector_type",
            "decoder_name",
            "file_path",
            "line",
            "verification",
        ]
        rows: list[dict[str, object]] = []
        for path in sorted(self.results_root.glob("*/*/trufflehog/findings.json")):
            try:
                package_id = path.parents[2].name
                version_code = path.parents[1].name
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(loaded, list):
                continue
            for finding in loaded:
                if isinstance(finding, dict):
                    rows.append(
                        {
                            "package_id": package_id,
                            "version_code": version_code,
                            **{field: finding.get(field, "") for field in fields if field not in {"package_id", "version_code"}},
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

    def run(self, *, limit: int | None = None, force: bool = False) -> AnalysisSummary:
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1 when supplied")
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
            base_dir = self.results_root / package_id / version_code
            directories = [base_dir / "jadx", base_dir / "apktool"]
            self._update_status(row, "running")
            try:
                findings = self._run_one(package_id, version_code, directories)
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
