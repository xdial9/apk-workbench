"""Safe JSON and HTML reports for acquired and analyzed APKs."""
from __future__ import annotations

import html
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


_FINDING_FIELDS = (
    "fingerprint",
    "detector_name",
    "detector_type",
    "decoder_name",
    "file_path",
    "line",
    "verification",
)


class ReportGenerator:
    """Generate individual reports using only explicitly allowlisted sanitized fields."""

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
    def _read_sanitized_findings(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReportingError(f"Cannot read sanitized findings at {path}: {exc}") from exc
        if not isinstance(data, list):
            raise ReportingError(f"Sanitized findings at {path} must contain a JSON array.")
        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            # Never copy arbitrary scanner fields into reports: Raw, RawV2,
            # Redacted, ExtraData, and StructuredData are intentionally excluded.
            findings.append({field: item.get(field, "") for field in _FINDING_FIELDS})
        return findings

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
            "<p class='muted'>Credential verification was disabled. Findings are unverified indicators for manual review.</p>",
        ]
        if findings:
            parts.extend(
                [
                    "<table><thead><tr><th>Detector</th><th>File</th><th>Line</th><th>Fingerprint</th></tr></thead><tbody>"
                ]
            )
            for finding in findings:
                parts.append(
                    "<tr>"
                    f"<td>{html.escape(str(finding.get('detector_name', '')))}</td>"
                    f"<td><code>{html.escape(str(finding.get('file_path', '')))}</code></td>"
                    f"<td>{html.escape(str(finding.get('line', '')))}</td>"
                    f"<td><code>{html.escape(str(finding.get('fingerprint', '')))}</code></td>"
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
                self._read_sanitized_findings(findings_path)
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
                "analysis": {"verification": "disabled", "finding_count": len(findings)},
                "findings": findings,
            }
            output_dir = self.reports_root / package_id / version_code / digest
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                output_dir.resolve(strict=True).relative_to(self.reports_root)
                if any(part.is_symlink() for part in (
                    self.reports_root / package_id,
                    self.reports_root / package_id / version_code,
                    output_dir,
                )):
                    raise ValueError("symlinked report output component")
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
