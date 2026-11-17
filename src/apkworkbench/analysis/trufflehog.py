"""Sequential local TruffleHog scanning - hand AI EVERYTHING.

One pass, complete --results set, split verified + unverified. Never drop unverified.
AI is the final tool, it decides what matters.
"""
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
from collections.abc import Callable
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
    """Scan completed decompilations and retain EVERYTHING: verified + unverified.

No dropping. Unverified is signal for AI, not noise.
"""

    REQUIRED_HELP_FLAGS = (
        "--results",
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
        progress: Callable[[str], None] | None = None,
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
        self.progress = progress
        self._help_checked = False
        # The --results value is resolved once from ``filesystem --help`` so we
        # emit a value the installed binary actually accepts.  Older TruffleHog
        # accepted ``--results=all``; 3.99.x replaced it with an explicit enum
        # (verified, unknown, unverified, filtered_unverified) and rejects any
        # other token.  The scanner still keeps every finding, never dropping
        # unverified, so the resolved value must name the complete set.
        self._results_flag = "all"

    def _emit_progress(self, message: str) -> None:
        if self.progress is None:
            return
        try:
            self.progress(message)
        except OSError:
            self.progress = None

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
        # Kong may advertise a boolean option as --[no-]flag, which explicitly
        # documents both its positive and negative forms.
        def supported(flag: str) -> bool:
            if flag in help_text:
                return True
            # Kong renders Boolean options as --[no-]<full-option-name>.
            return flag.startswith("--") and f"--[no-]{flag[2:]}" in help_text

        missing = [flag for flag in self.REQUIRED_HELP_FLAGS if not supported(flag)]
        if missing:
            raise AnalysisError(
                "Installed TruffleHog filesystem command does not advertise required safe "
                "flags: " + ", ".join(missing) + ". No scan was started."
            )
        # Resolve the --results enum.  ``all`` is the legacy token; 3.99.x lists
        # the individual categories instead.  A comma-separated superset of every
        # advertised category is equivalent to the legacy ``all`` and keeps every
        # finding (the scanner splits verified/unverified afterward, never drops).
        advertised = {
            token for token in ("verified", "unknown", "unverified", "filtered_unverified")
            if token in help_text
        }
        if advertised:
            self._results_flag = ",".join(sorted(advertised))
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

    @classmethod
    def _verified_text_report(
        cls,
        package_id: str,
        version_code: str,
        digest: str,
        verified: list[dict[str, Any]],
        unverified_count: int,
    ) -> str:
        """Human-facing, verified-only plain-text summary.

        The machine plane (findings.json + the two split files) keeps everything
        for the AI handoff; this file is the short read a person opens first.
        """
        lines = [
            "APK WORKBENCH — VERIFIED SECRET FINDINGS",
            "========================================",
            f"package_id  : {package_id}",
            f"version_code: {version_code}",
            f"apk_sha256  : {digest}",
            f"verified    : {len(verified)}",
            f"unverified  : {unverified_count} (retained for the AI handoff; not listed here)",
            "",
        ]
        if not verified:
            lines.append("No verified secret findings for this artifact.")
            lines.append("")
            return "\n".join(lines)
        for index, item in enumerate(verified, start=1):
            file_path, line_number = cls._filesystem_metadata(item)
            lines.extend([
                (
                    f"[{index}] {item.get('DetectorName') or 'TruffleHog finding'}"
                    f" (detector type {item.get('DetectorType', 'unknown')})"
                ),
                f"    decoder     : {item.get('DecoderName') or 'unknown'}",
                f"    file        : {file_path or 'unknown'}",
                f"    line        : {line_number if line_number is not None else 'unknown'}",
                "    verification: VERIFIED",
                f"    raw         : {item.get('Raw') or item.get('RawV2') or ''}",
                "",
            ])
        return "\n".join(lines)

    @classmethod
    def _all_findings_text_report(
        cls,
        package_id: str,
        version_code: str,
        digest: str,
        findings: list[dict[str, Any]],
        verified_count: int,
    ) -> str:
        """Human-facing plain-text summary of EVERY TruffleHog finding.

        Unlike the verified-only short read, this lists verified AND unverified
        findings so a human can review the complete secret surface. The machine
        plane (findings.json + the split files) keeps everything for the AI
        handoff; this file is the human-readable companion.
        """
        unverified_count = len(findings) - verified_count
        lines = [
            "APK WORKBENCH — ALL TRUFFLEHOG FINDINGS",
            "==========================================",
            f"package_id  : {package_id}",
            f"version_code: {version_code}",
            f"apk_sha256  : {digest}",
            f"verified    : {verified_count}",
            f"unverified  : {unverified_count} (retained for the AI handoff)",
            f"total       : {len(findings)}",
            "",
        ]
        if not findings:
            lines.append("No TruffleHog findings for this artifact.")
            lines.append("")
            return "\n".join(lines)
        for index, item in enumerate(findings, start=1):
            file_path, line_number = cls._filesystem_metadata(item)
            verification = "VERIFIED" if item.get("Verified") is True else "UNVERIFIED"
            lines.extend([
                (
                    f"[{index}] {item.get('DetectorName') or 'TruffleHog finding'}"
                    f" (detector type {item.get('DetectorType', 'unknown')})"
                ),
                f"    decoder       : {item.get('DecoderName') or 'unknown'}",
                f"    file          : {file_path or 'unknown'}",
                f"    line          : {line_number if line_number is not None else 'unknown'}",
                f"    verification  : {verification}",
                f"    raw           : {item.get('Raw') or item.get('RawV2') or ''}",
                "",
            ])
        return "\n".join(lines)

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
    def _atomic_bytes(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
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
            raise AnalysisError(f"Cannot publish scanner evidence {path.name}: {exc}") from exc
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
            "--concurrency=1",
            "--no-update",
            f"--results={self._results_flag}",
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
            started = time.monotonic()
            last_progress = started
            progress_line = bytearray()
            live_verified_count = 0
            live_total_count = 0
            previous_sigterm = None

            def handle_sigterm(signum, _frame):
                raise KeyboardInterrupt(f"received signal {signum}")

            try:
                try:
                    previous_sigterm = signal.signal(signal.SIGTERM, handle_sigterm)
                except ValueError:
                    # Signal handlers can only be installed from the main thread.
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
                        now = time.monotonic()
                        if not events:
                            if self.progress is not None and now - last_progress >= 1.0:
                                self._emit_progress(
                                    f"[TruffleHog] scanning {package_id} — "
                                    f"{int(now - started)}s elapsed, {output_size:,} JSON bytes, "
                                    f"{live_total_count} total, {live_verified_count} verified"
                                )
                                last_progress = now
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
                            if self.progress is not None:
                                progress_line.extend(chunk)
                                while b"\n" in progress_line:
                                    raw_line, progress_line = progress_line.split(b"\n", 1)
                                    try:
                                        live_item = json.loads(raw_line.decode("utf-8"))
                                    except (UnicodeDecodeError, json.JSONDecodeError):
                                        live_item = None
                                    if isinstance(live_item, dict):
                                        live_total_count += 1
                                        if live_item.get("Verified") is True:
                                            live_verified_count += 1
                                        detector = live_item.get("DetectorName") or "verified finding"
                                        self._emit_progress(
                                            f"[TruffleHog] VERIFIED finding #{live_verified_count}: {detector}"
                                        )
                                if time.monotonic() - last_progress >= 1.0:
                                    now = time.monotonic()
                                    self._emit_progress(
                                        f"[TruffleHog] scanning {package_id} — "
                                        f"{int(now - started)}s elapsed, {output_size:,} JSON bytes, "
                                        f"{live_total_count} total, {live_verified_count} verified"
                                    )
                                    last_progress = now
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
            stdout_file.seek(0)
            raw_stdout = stdout_file.read()
            stderr_file.seek(0)
            raw_stderr = stderr_file.read()

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
        # CAP-FREE / VERIFIED-ONLY REVERSAL: Never drop unverified. Split, don't filter.
        # total_seen must equal verified + unverified. Empty means empty.
        verified_findings = [item for item in findings if item.get("Verified") is True]
        unverified_findings = [item for item in findings if item.get("Verified") is not True]
        assert len(verified_findings) + len(unverified_findings) == len(findings), "split must preserve total"

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
        # findings.json = ALL findings (backwards compat: callers that read findings.json now get everything)
        # findings-verified.json = verified only, findings-unverified.json = unverified only
        # scan.json = counts, invariant total_seen == verified + unverified
        self._atomic_json(output_dir / "findings.json", findings)
        self._atomic_json(output_dir / "findings-verified.json", verified_findings)
        self._atomic_json(output_dir / "findings-unverified.json", unverified_findings)
        self._atomic_json(output_dir / "scan.json", {
            "total_seen": len(findings),
            "verified": len(verified_findings),
            "unverified": len(unverified_findings),
            "results_flag": self._results_flag,
            "package_id": package_id,
            "version_code": version_code,
            "sha256": digest,
        })
        self._atomic_bytes(output_dir / "stdout.jsonl", raw_stdout)
        self._atomic_bytes(output_dir / "stderr.log", raw_stderr)
        # Human-facing verified-only summary. The machine files above keep
        # verified + unverified for the AI handoff; this .txt is the short read.
        self._atomic_bytes(
            output_dir / "findings-verified.txt",
            self._verified_text_report(
                package_id, version_code, digest, verified_findings, len(unverified_findings)
            ).encode("utf-8"),
        )
        # Human-facing complete summary: EVERY TruffleHog finding (verified +
        # unverified), each with its verification status. This .txt is the
        # single human-readable artifact for the secret surface.
        self._atomic_bytes(
            output_dir / "findings-all.txt",
            self._all_findings_text_report(
                package_id, version_code, digest, findings, len(verified_findings)
            ).encode("utf-8"),
        )
        if self.progress is not None:
            self._emit_progress(
                f"[TruffleHog] COMPLETE: {package_id}; {len(findings)} total "
                f"({len(verified_findings)} verified, {len(unverified_findings)} unverified); "
                f"{output_size:,} JSON bytes; exit code {return_code}"
            )
        log_text = (
            f"COMMAND: {json.dumps(command)}\n"
            f"RETURN CODE: {return_code}\n"
            f"FINDINGS EMITTED: {len(findings)}\n"
            f"VERIFIED FINDINGS: {len(verified_findings)}\n"
            f"UNVERIFIED FINDINGS: {len(unverified_findings)}\n"
            f"TOTAL_SEEN: {len(findings)}\n"
            "CREDENTIAL VERIFICATION: ENABLED, RESULTS NOT FILTERED\n"
            f"RESULT SELECTION: --results={self._results_flag} (verified + unverified)\n"
            "STDOUT EVIDENCE: stdout.jsonl\n"
            "STDERR EVIDENCE: stderr.log\n"
        )
        self._atomic_bytes(output_dir / "trufflehog.log", log_text.encode("utf-8"))
        return findings

    def _has_usable_scan_output(
        self, package_id: str, version_code: str, digest: str
    ) -> bool:
        """Reuse a successful scan only while its complete JSON result files remain valid."""
        output_dir = (
            self.results_root / package_id / version_code / digest / "trufflehog"
        )
        findings_path = output_dir / "findings.json"
        scan_path = output_dir / "scan.json"
        verified_path = output_dir / "findings-verified.json"
        unverified_path = output_dir / "findings-unverified.json"
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
            if not isinstance(findings, list):
                return False
            # New format: scan.json must exist and invariant must hold
            if scan_path.is_file():
                scan = json.loads(scan_path.read_text(encoding="utf-8"))
                if not isinstance(scan, dict):
                    return False
                total = scan.get("total_seen")
                verified_n = scan.get("verified")
                unverified_n = scan.get("unverified")
                if total != len(findings):
                    return False
                if verified_n is not None and unverified_n is not None and verified_n + unverified_n != total:
                    return False
                # If split files exist, they must also match counts
                if verified_path.is_file() and unverified_path.is_file():
                    v = json.loads(verified_path.read_text(encoding="utf-8"))
                    u = json.loads(unverified_path.read_text(encoding="utf-8"))
                    if not isinstance(v, list) or not isinstance(u, list):
                        return False
                    if len(v) + len(u) != len(findings):
                        return False
            # Old format (verified-only, pre-split) is still usable if all verified,
            # but new scans must have scan.json. Accept old files as usable to avoid rescanning.
            return all(isinstance(item, dict) for item in findings)
        except (OSError, ValueError, json.JSONDecodeError):
            return False

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
        fields = ["package_id", "version_code", "sha256", "detector_name", "detector_type", "decoder_name", "file_path", "line", "verification", "finding_json"]
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
                    # Hand AI everything: verified + unverified in aggregate CSV
                    is_verified = finding.get("Verified") is True
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
                            "verification": "verified" if is_verified else "unverified",
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
            if previous.get("apktool_status") not in {"success", "partial"}:
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
            directories = [base_dir / "apktool"]
            self._update_status(row, "running")
            if self.progress is not None:
                self._emit_progress(f"[TruffleHog] starting {package_id} v{version_code} — all results (verified + unverified)")
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
