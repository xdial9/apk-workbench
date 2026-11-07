"""Safe JSON and HTML reports for acquired and analyzed APKs."""
from __future__ import annotations

import html
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..database.workspace import WorkspaceDatabase


class ReportingError(RuntimeError):
    """Raised when an artifact report cannot be generated safely."""


@dataclass(frozen=True)
class ReportSummary:
    generated: int
    with_findings: int
    total_findings: int



class ReportGenerator:
    """Generate reports containing complete original TruffleHog finding objects."""

    def __init__(self, database: WorkspaceDatabase, *, workspace: str | Path):
        self.database = database
        self.workspace = Path(workspace).expanduser().resolve()
        self.results_root = self.workspace / "results"
        self.reports_root = self.workspace / "reports"

    @staticmethod
    def _safe_path_parts(package_id: str, version_code: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
            raise ReportingError(f"Unsafe package ID in download history: {package_id!r}")
        if not version_code.isdigit():
            raise ReportingError(f"Unsafe version code in download history: {version_code!r}")

    @staticmethod
    def _read_findings(path: Path) -> list[dict[str, Any]]:
        if path.is_symlink():
            raise ReportingError(f"Refusing to read a symlinked findings file: {path}")
        if not path.exists():
            raise ReportingError(
                f"Findings file is missing despite a successful scan: {path}"
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReportingError(f"Cannot read findings at {path}: {exc}") from exc
        if not isinstance(data, list):
            raise ReportingError(f"Findings at {path} must contain a JSON array.")
        if not all(isinstance(item, dict) for item in data):
            raise ReportingError(f"Findings at {path} must contain only JSON objects.")
        if any(item.get("Verified") is not True for item in data):
            raise ReportingError(
                f"Findings at {path} contain records that are not explicitly verified."
            )
        return data

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
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
        except OSError as exc:
            raise ReportingError(f"Cannot publish report {path}: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _html_report(report: dict[str, Any]) -> str:
        artifact = report["artifact"]
        status = report["processing"]
        findings = report["findings"]
        title_text = f"{artifact['package_id']} {artifact['version_name'] or artifact['version_code']}"
        parts = [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{html.escape(title_text)}</title>",
            "<style>",
            "body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#222}",
            "h1,h2{line-height:1.25}table{border-collapse:collapse;width:100%;margin:1rem 0}",
            "th,td{text-align:left;vertical-align:top;padding:.55rem;border:1px solid #ccc;overflow-wrap:anywhere}",
            "th{background:#eee}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.5rem}",
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:70vw}",
            "code{font-size:.9em;overflow-wrap:anywhere}.muted{color:#555}",
            "</style></head><body>",
            f"<h1>{html.escape(title_text)}</h1>",
            "<h2>Artifact</h2><dl class='meta'>",
            f"<dt>Package ID</dt><dd>{html.escape(str(artifact['package_id']))}</dd>",
            f"<dt>Version code</dt><dd>{html.escape(str(artifact['version_code']))}</dd>",
            f"<dt>Version name</dt><dd>{html.escape(str(artifact['version_name']))}</dd>",
            f"<dt>SHA-256</dt><dd><code>{html.escape(str(artifact['sha256']))}</code></dd>",
            f"<dt>APK size</dt><dd>{html.escape(str(artifact['size']))} bytes</dd>",
            f"<dt>Downloaded</dt><dd>{html.escape(str(artifact['downloaded_at']))}</dd>",
            "</dl>",
            "<h2>Processing status</h2><ul>",
            f"<li>JADX: {html.escape(str(status.get('jadx_status', 'pending')))}</li>",
            f"<li>Apktool: {html.escape(str(status.get('apktool_status', 'pending')))}</li>",
            f"<li>TruffleHog: {html.escape(str(status.get('scan_status', 'pending')))}</li>",
            "</ul>",
            f"<h2>Static analysis candidates ({len(findings)})</h2>",
            "<p class='muted'>Credential verification was enabled; TruffleHog selected verified findings.</p>",
        ]
        if findings:
            parts.extend(
                [
                    "<table><thead><tr><th>Detector</th><th>File</th><th>Line</th><th>Fingerprint</th><th>Complete original JSON</th></tr></thead><tbody>"
                ]
            )
            for finding in findings:
                source_metadata = finding.get("SourceMetadata")
                source_data = source_metadata.get("Data", {}) if isinstance(source_metadata, dict) else {}
                filesystem = source_data.get("Filesystem", {}) if isinstance(source_data, dict) else {}
                if not isinstance(filesystem, dict):
                    filesystem = {}
                file_path = filesystem.get("file", "")
                line_number = filesystem.get("line", "")
                fingerprint = hashlib.sha256(
                    json.dumps(finding, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                parts.append(
                    "<tr>"
                    f"<td>{html.escape(str(finding.get('DetectorName', '')))}</td>"
                    f"<td><code>{html.escape(str(file_path))}</code></td>"
                    f"<td>{html.escape(str(line_number))}</td>"
                    f"<td><code>{html.escape(fingerprint)}</code></td>"
                    f"<td><details><summary>View all fields</summary><pre>{html.escape(json.dumps(finding, ensure_ascii=False, indent=2))}</pre></details></td>"
                    "</tr>"
                )
            parts.append("</tbody></table>")
        else:
            parts.append("<p>No candidate findings were recorded.</p>")
        parts.extend(["</body></html>", ""])
        return "\n".join(parts)

    def _validate_workspace_roots(self) -> None:
        for label, root in (
            ("results", self.results_root),
            ("reports", self.reports_root),
        ):
            if root.is_symlink():
                raise ReportingError(
                    f"The {label} directory resolves outside or aliases the configured workspace."
                )
            root.mkdir(parents=True, exist_ok=True)
            try:
                root.resolve(strict=True).relative_to(self.workspace)
            except (OSError, ValueError) as exc:
                raise ReportingError(
                    f"The {label} directory resolves outside the configured workspace."
                ) from exc
        self.results_root = self.results_root.resolve(strict=True)
        self.reports_root = self.reports_root.resolve(strict=True)

    def run(self) -> ReportSummary:
        self._validate_workspace_roots()
        self.database.ensure()
        history = self.database.read_download_history()
        statuses = self.database.read_processing_status()
        generated = with_findings = total_findings = 0

        for row in history:
            package_id = row.get("package_id", "")
            version_code = row.get("version_code", "")
            self._safe_path_parts(package_id, version_code)
            digest = row.get("sha256", "").lower()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ReportingError(f"Malformed SHA-256 in download history: {digest!r}")
            status = statuses.get(digest, {})
            findings_path = (
                self.results_root / package_id / version_code / digest / "trufflehog" / "findings.json"
            )
            try:
                findings_path.resolve().relative_to(self.results_root.resolve())
            except ValueError as exc:
                raise ReportingError("Finding path resolves outside the results workspace.") from exc
            findings = (
                self._read_findings(findings_path)
                if status.get("scan_status") == "success"
                else []
            )
            artifact = {
                "package_id": package_id,
                "app_name": row.get("app_name", ""),
                "version_code": version_code,
                "version_name": row.get("version_name", ""),
                "sha256": digest,
                "size": int(row.get("size") or 0),
                "source": row.get("source", ""),
                "downloaded_at": row.get("downloaded_at", ""),
                "index_sha256": row.get("index_sha256", ""),
            }
            processing = {
                "jadx_status": status.get("jadx_status", "pending"),
                "apktool_status": status.get("apktool_status", "pending"),
                "scan_status": status.get("scan_status", "pending"),
            }
            report = {
                "schema_version": 1,
                "artifact": artifact,
                "processing": processing,
                "analysis": {"verification": "enabled", "finding_count": len(findings)},
                "findings": findings,
            }
            output_dir = self.reports_root / package_id / version_code / digest
            try:
                output_components = (
                    self.reports_root / package_id,
                    self.reports_root / package_id / version_code,
                    output_dir,
                )
                if any(part.is_symlink() for part in output_components):
                    raise ValueError("symlinked report output component")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_dir.resolve(strict=True).relative_to(self.reports_root)
            except (OSError, ValueError) as exc:
                raise ReportingError(
                    f"Report output path escapes or aliases the reports workspace: {output_dir}"
                ) from exc
            json_text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
            self._atomic_write(output_dir / "report.json", json_text)
            self._atomic_write(output_dir / "report.html", self._html_report(report))
            generated += 1
            total_findings += len(findings)
            if findings:
                with_findings += 1

        return ReportSummary(generated, with_findings, total_findings)
