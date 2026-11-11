"""One consolidated evidence package for a complete APK Workbench run."""
from __future__ import annotations

import html
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from apkworkbench.database.workspace import WorkspaceDatabase


class FinalRunReportError(RuntimeError):
    """Raised when a consolidated run report cannot be assembled."""


def _read_json(path: Path, root: Path) -> Any | None:
    if path.is_symlink():
        raise FinalRunReportError(f"Refusing symlinked report input: {path}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        return json.loads(resolved.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise FinalRunReportError(f"Cannot read run evidence {path}: {exc}") from exc


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
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
    finally:
        temporary.unlink(missing_ok=True)


def _html_document(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    title = f"APK Workbench — Run {payload['run']['run_id']}"
    summary_json = html.escape(json.dumps(summary, ensure_ascii=False, indent=2))
    full_json = html.escape(json.dumps(payload, ensure_ascii=False, indent=2))
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html.escape(title)}</title>",
        "<style>",
        "body{font:15px system-ui,sans-serif;max-width:1250px;margin:2rem auto;padding:0 1rem;color:#222}",
        "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;vertical-align:top;border:1px solid #ccc;padding:.5rem;overflow-wrap:anywhere}",
        "th{background:#f0f0f0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f5f5;padding:1rem;border-radius:8px}",
        "summary{cursor:pointer;font-weight:650;margin:.8rem 0}code{overflow-wrap:anywhere}.muted{color:#555}",
        ".finding{border:1px solid #ddd;border-radius:8px;padding:.8rem;margin:.6rem 0}",
        "</style></head><body>",
        f"<h1>{html.escape(title)}</h1>",
        "<p>Consolidated acquisition, independent verification, Apktool, APK surface analysis, verified-secret scan, API inventory, reports and reconciliation.</p>",
        "<h2>Run summary</h2>",
        f"<pre>{summary_json}</pre>",
        "<h2>API inventory</h2>",
    ]

    api_catalog = payload.get("api_catalog", {})
    endpoints = api_catalog.get("endpoint_candidates", [])
    routes = api_catalog.get("route_candidates", [])
    call_sites = api_catalog.get("smali_api_call_sites", [])
    parts.append(f"<p>Endpoint/domain candidates: {len(endpoints)} · Route candidates: {len(routes)} · Smali API call sites: {len(call_sites)}</p>")
    if endpoints:
        parts.append("<h3>Endpoint and domain candidates</h3><table><thead><tr><th>Endpoint</th><th>Kind</th><th>Occurrences</th><th>Evidence</th><th>Nearby client rate-limit clues</th></tr></thead><tbody>")
        for item in endpoints:
            locations = item.get("evidence", [])
            evidence = "; ".join(
                f"{html.escape(str(loc.get('path', '')))}:{html.escape(str(loc.get('line', '')))}"
                for loc in locations
            )
            nearby = item.get("nearby_rate_limit_indicators", [])
            signal_text = "; ".join(
                f"{html.escape(str(sig.get('path', '')))}:{html.escape(str(sig.get('line', '')))}"
                for sig in nearby
            ) or "No nearby client-side clue found"
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(item.get('value', '')))}</code></td>"
                f"<td>{html.escape(str(item.get('kind', '')))}</td>"
                f"<td>{html.escape(str(item.get('occurrences', 0)))}</td>"
                f"<td>{evidence}</td><td>{signal_text}</td></tr>"
            )
        parts.append("</tbody></table>")
    if routes:
        parts.append("<h3>API route candidates</h3><table><thead><tr><th>Method</th><th>Route</th><th>Occurrences</th><th>Evidence</th></tr></thead><tbody>")
        for item in routes:
            evidence = "; ".join(
                f"{html.escape(str(loc.get('path', '')))}:{html.escape(str(loc.get('line', '')))}"
                for loc in item.get("evidence", [])
            )
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(item.get('http_method') or 'UNKNOWN'))}</td>"
                f"<td><code>{html.escape(str(item.get('path', '')))}</code></td>"
                f"<td>{html.escape(str(item.get('occurrences', 0)))}</td>"
                f"<td>{evidence}</td></tr>"
            )
        parts.append("</tbody></table>")
    if call_sites:
        parts.append("<h3>Smali network/API call sites</h3><table><thead><tr><th>Owner</th><th>Method</th><th>Evidence</th><th>Invocation</th></tr></thead><tbody>")
        for item in call_sites:
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(item.get('owner', '')))}</code></td>"
                f"<td>{html.escape(str(item.get('method', '')))}</td>"
                f"<td>{html.escape(str(item.get('path', '')))}:{html.escape(str(item.get('line', '')))}</td>"
                f"<td><code>{html.escape(str(item.get('snippet', '')))}</code></td></tr>"
            )
        parts.append("</tbody></table>")
    dex_methods = api_catalog.get("androguard_external_method_references", [])
    dex_strings = api_catalog.get("androguard_api_related_strings", [])
    permission_usage = api_catalog.get("androguard_permission_api_usage", [])
    parts.append(
        f"<h3>Androguard DEX cross-reference inventory</h3>"
        f"<p>External API/library methods: {len(dex_methods)} · "
        f"DEX API/config strings: {len(dex_strings)} · "
        f"Permission-to-API call groups: {len(permission_usage)}</p>"
    )
    if dex_methods:
        parts.append("<details><summary>All external DEX method references and callers</summary><table><thead><tr><th>External method</th><th>Category</th><th>Android API</th><th>Call sites</th></tr></thead><tbody>")
        for item in dex_methods:
            callers = "; ".join(
                f"{html.escape(str(call.get('caller', '')))} @ {html.escape(str(call.get('offset', '')))}"
                for call in item.get("call_sites", [])
            )
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(item.get('full_name', '')))}</code></td>"
                f"<td>{html.escape(str(item.get('category', '')))}</td>"
                f"<td>{html.escape(str(item.get('android_api', '')))}</td>"
                f"<td>{callers}</td></tr>"
            )
        parts.append("</tbody></table></details>")
    if dex_call_graph:
        parts.append("<details><summary>All internal DEX call-graph edges</summary><table><thead><tr><th>Caller</th><th>Callee</th><th>Offset</th></tr></thead><tbody>")
        for item in dex_call_graph:
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(item.get('caller', '')))}</code></td>"
                f"<td><code>{html.escape(str(item.get('callee', '')))}</code></td>"
                f"<td>{html.escape(str(item.get('offset', '')))}</td></tr>"
            )
        parts.append("</tbody></table></details>")
    if dex_strings:
        parts.append("<details><summary>All DEX API-related strings with caller references</summary><table><thead><tr><th>String</th><th>URLs/domains/IPs</th><th>Route</th><th>Relative path</th><th>Network-call context</th><th>Rate-limit/header clue</th><th>DEX references</th></tr></thead><tbody>")
        for item in dex_strings:
            addresses = ", ".join(
                [*item.get("urls", []), *item.get("domains", []), *item.get("ip_addresses", [])]
            )
            refs = "; ".join(
                f"{html.escape(str(ref.get('caller', '')))} @ {html.escape(str(ref.get('offset', '')))}"
                for ref in item.get("references", [])
            )
            clue = bool(item.get("rate_limit_or_retry_indicator") or item.get("http_header_candidates"))
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(item.get('value', '')))}</code></td>"
                f"<td>{html.escape(addresses)}</td>"
                f"<td>{html.escape(str(item.get('route_candidate', False)))}</td>"
                f"<td>{html.escape(str(item.get('relative_path_candidate', False)))}</td>"
                f"<td>{html.escape(str(item.get('network_call_context', False)))}</td>"
                f"<td>{html.escape(str(clue))}</td>"
                f"<td>{refs}</td></tr>"
            )
        parts.append("</tbody></table></details>")
    if permission_usage:
        parts.append("<details><summary>Android permission-sensitive API usage and callers</summary><table><thead><tr><th>Android API method</th><th>Permissions mapped</th><th>Callers</th></tr></thead><tbody>")
        for item in permission_usage:
            callers = "; ".join(
                f"{html.escape(str(call.get('caller', '')))} @ {html.escape(str(call.get('offset', '')))}"
                for call in item.get("call_sites", [])
            )
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(item.get('api_method', '')))}</code></td>"
                f"<td>{html.escape(', '.join(item.get('permissions', [])))}</td>"
                f"<td>{callers}</td></tr>"
            )
        parts.append("</tbody></table></details>")
    parts.append(
        "<p class='muted'>Rate-limit note: static APK evidence can reveal client retry/backoff behavior and header use, "
        "but cannot establish server-side quotas. A missing client-side clue does not mean an API is unthrottled. "
        "Androguard permission mappings are version-specific and may be incomplete.</p>"
    )

    parts.append("<h2>Artifact analysis and findings</h2>")
    for artifact in payload.get("artifacts", []):
        metadata = artifact.get("artifact", {})
        static = artifact.get("static_analysis", {})
        findings = artifact.get("findings", {})
        static_items = findings.get("static_indicators", [])
        verified_items = findings.get("trufflehog_verified_original_objects", [])
        parts.append(
            f"<h3>{html.escape(str(metadata.get('package_id', 'unknown')))} "
            f"v{html.escape(str(metadata.get('version_code', 'unknown')))} "
            f"— {html.escape(str(metadata.get('sha256', '')))}</h3>"
        )
        dex = static.get("dex_analysis", {})
        if isinstance(dex, dict):
            metrics = dex.get("metrics", {})
            parts.append(
                "<h4>Androguard DEX analysis</h4>"
                f"<p>Status: {html.escape(str(dex.get('status', 'not_run')))} · "
                f"DEX files: {html.escape(str(metrics.get('dex_files', 0)))} · "
                f"Classes: {html.escape(str(metrics.get('classes', 0)))} · "
                f"Internal methods: {html.escape(str(metrics.get('internal_methods', 0)))} · "
                f"External methods: {html.escape(str(metrics.get('external_methods_referenced', 0)))}</p>"
            )
            if dex.get("diagnostics"):
                parts.append("<details><summary>Androguard diagnostics</summary><pre>")
                parts.append(html.escape(json.dumps(dex.get("diagnostics"), ensure_ascii=False, indent=2)))
                parts.append("</pre></details>")
        parts.append("<h4>Static-analysis coverage</h4>")
        coverage = static.get("coverage", {})
        if coverage:
            parts.append("<table><thead><tr><th>Area</th><th>Status</th></tr></thead><tbody>")
            for area, status in sorted(coverage.items()):
                parts.append(
                    f"<tr><td>{html.escape(str(area))}</td><td>{html.escape(str(status))}</td></tr>"
                )
            parts.append("</tbody></table>")
        else:
            parts.append("<p>Static surface analysis did not complete or was not run.</p>")
        parts.append(f"<h4>Static indicators ({len(static_items)})</h4>")
        if static_items:
            for finding in static_items:
                evidence = finding.get("evidence", {})
                parts.append(
                    "<div class='finding'>"
                    f"<strong>{html.escape(str(finding.get('severity', 'info')).upper())}: "
                    f"{html.escape(str(finding.get('title', 'Static indicator')))}</strong>"
                    f"<p>{html.escape(str(finding.get('message', '')))}</p>"
                    f"<p class='muted'>Rule: {html.escape(str(finding.get('rule_id', '')))} · "
                    f"Confidence: {html.escape(str(finding.get('confidence', '')))} · "
                    f"Verification: {html.escape(str(finding.get('verification_state', 'static_unverified')))}</p>"
                    f"<p>Evidence: <code>{html.escape(str(evidence.get('path', '')))}"
                    f":{html.escape(str(evidence.get('line', '')))}</code></p>"
                    f"<details><summary>Original evidence line</summary><pre>{html.escape(str(evidence.get('snippet', '')))}</pre></details>"
                    "</div>"
                )
        else:
            parts.append("<p>No static indicators were emitted. Review the coverage and limitations before interpreting this as a clean assessment.</p>")
        parts.append(f"<h4>TruffleHog verified findings ({len(verified_items)})</h4>")
        if verified_items:
            for finding in verified_items:
                detector = finding.get("DetectorName", "Verified finding")
                parts.append(
                    "<details class='finding'><summary>"
                    f"{html.escape(str(detector))} — complete original finding object"
                    "</summary><pre>"
                    f"{html.escape(json.dumps(finding, ensure_ascii=False, indent=2))}"
                    "</pre></details>"
                )
        else:
            parts.append("<p>No TruffleHog verified findings were emitted for this artifact.</p>")
        limitations = static.get("limitations", [])
        if limitations:
            parts.append("<h4>Analysis limitations</h4><ul>")
            parts.extend(f"<li>{html.escape(str(item))}</li>" for item in limitations)
            parts.append("</ul>")

    parts.extend([
        "<h2>Complete machine-readable evidence</h2>",
        "<details><summary>Expand all raw run evidence, manifest entries, stage results and original findings JSON</summary>",
        f"<pre>{full_json}</pre></details>",
        "</body></html>",
        "",
    ])
    return "\n".join(parts)


def generate_final_run_report(
    database: WorkspaceDatabase,
    workspace: str | Path,
    run_id: str,
) -> dict[str, Any]:
    """Collect exact manifest scope, stage outcomes, API catalog and complete findings."""
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", run_id):
        raise FinalRunReportError("Run ID contains invalid characters.")

    root = Path(workspace).expanduser().resolve()
    reports_root = root / "reports"
    results_root = root / "results"
    for label, path in (("reports", reports_root), ("results", results_root)):
        if path.is_symlink():
            raise FinalRunReportError(f"The {label} directory must not be a symlink.")
        path.mkdir(parents=True, exist_ok=True)
        path.resolve(strict=True).relative_to(root)

    manifest = database.read_manifest(run_id)
    if not manifest:
        raise FinalRunReportError(f"Run {run_id} has no manifest entries.")
    history = database.read_download_history()
    attempts = database.read_download_attempts()
    run_attempts = [item for item in attempts if item.get("run_id") == run_id]
    statuses = database.read_processing_status()
    history_by_hash = {row.get("sha256", "").lower(): row for row in history if row.get("sha256")}

    verification_path = reports_root / f"phase_one_verification_{run_id}.json"
    verification = _read_json(verification_path, reports_root)
    surface_run_path = results_root / "runs" / run_id / "static-analysis-run.json"
    surface_run_record = _read_json(surface_run_path, results_root)

    reconciliation = database.reconcile_run(run_id)
    artifacts: list[dict[str, Any]] = []
    api_endpoints: list[dict[str, Any]] = []
    api_routes: list[dict[str, Any]] = []
    api_clients: list[dict[str, Any]] = []
    api_call_sites: list[dict[str, Any]] = []
    api_headers: list[dict[str, Any]] = []
    rate_limit_indicators: list[dict[str, Any]] = []
    dex_external_methods: list[dict[str, Any]] = []
    dex_internal_call_graph: list[dict[str, Any]] = []
    dex_api_strings: list[dict[str, Any]] = []
    dex_permission_api_usage: list[dict[str, Any]] = []
    dex_rate_limit_indicators: list[dict[str, Any]] = []
    verified_findings = 0
    static_findings = 0
    api_endpoint_count = 0
    api_route_count = 0
    static_failed = 0
    trufflehog_failed = 0

    seen: set[tuple[str, str, str]] = set()
    for selected in manifest:
        package_id = selected.get("package_id", "")
        version_code = str(selected.get("version_code", ""))
        digest = selected.get("sha256", "").lower()
        identity = (package_id, version_code, digest)
        if identity in seen:
            continue
        seen.add(identity)
        acquired = history_by_hash.get(digest)
        if (
            acquired is None
            or acquired.get("run_id") != run_id
            or acquired.get("package_id") != package_id
            or str(acquired.get("version_code", "")) != version_code
            or acquired.get("source") != selected.get("source")
        ):
            acquired = None

        status = statuses.get(digest, {})
        bundle_dir = Path(acquired.get("local_path", "")).parent if acquired and acquired.get("local_path") else None
        bundle_path = bundle_dir / "google-play-bundle.json" if bundle_dir else None
        bundle_metadata = _read_json(bundle_path, root) if bundle_path else None

        artifact_root = results_root / package_id / version_code / digest
        static_path = artifact_root / "static-analysis.json"
        static_analysis = _read_json(static_path, results_root)
        trufflehog_dir = artifact_root / "trufflehog"
        trufflehog_path = trufflehog_dir / "findings.json"
        if status.get("scan_status") == "success":
            trufflehog_findings = _read_json(trufflehog_path, results_root)
            if trufflehog_findings is None:
                raise FinalRunReportError(
                    f"TruffleHog status says success but findings.json is missing for {package_id}."
                )
        else:
            # Never present an older findings file as the result of a failed or unrun scan.
            trufflehog_findings = []
        if not isinstance(trufflehog_findings, list) or any(
            not isinstance(item, dict) or item.get("Verified") is not True
            for item in trufflehog_findings
        ):
            raise FinalRunReportError(
                f"TruffleHog evidence for {package_id} contains non-verified or malformed records."
            )

        if isinstance(static_analysis, dict):
            static_list = static_analysis.get("findings", [])
            if not isinstance(static_list, list):
                static_list = []
            static_findings += len(static_list)
            api_inventory = static_analysis.get("inventory", {})
            if not isinstance(api_inventory, dict):
                api_inventory = {}
            endpoints = api_inventory.get("endpoints", [])
            routes = api_inventory.get("api_routes", [])
            clients = api_inventory.get("api_clients", [])
            call_sites = api_inventory.get("api_call_sites", [])
            headers = api_inventory.get("api_headers", [])
            limit_signals = api_inventory.get("rate_limit_indicators", [])
            if isinstance(clients, list):
                api_clients.extend({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, **entry,
                } for entry in clients if isinstance(entry, dict))
            if isinstance(call_sites, list):
                api_call_sites.extend({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, **entry,
                } for entry in call_sites if isinstance(entry, dict))
            if isinstance(headers, list):
                api_headers.extend({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, **entry,
                } for entry in headers if isinstance(entry, dict))
            if isinstance(limit_signals, list):
                rate_limit_indicators.extend({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, **entry,
                } for entry in limit_signals if isinstance(entry, dict))
            if isinstance(endpoints, list):
                api_endpoint_count += len(endpoints)
                api_endpoints.extend({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, **entry,
                } for entry in endpoints if isinstance(entry, dict))
            if isinstance(routes, list):
                api_route_count += len(routes)
                api_routes.extend({
                    "package_id": package_id, "version_code": version_code,
                    "sha256": digest, **entry,
                } for entry in routes if isinstance(entry, dict))
            dex_analysis = static_analysis.get("dex_analysis", {})
            if not isinstance(dex_analysis, dict):
                dex_analysis = {}
            for source_key, target_list in (
                ("external_method_references", dex_external_methods),
                ("internal_call_graph", dex_internal_call_graph),
                ("dex_api_strings", dex_api_strings),
                ("permission_api_usage", dex_permission_api_usage),
            ):
                values = dex_analysis.get(source_key, [])
                if isinstance(values, list):
                    target_list.extend({
                        "package_id": package_id, "version_code": version_code,
                        "sha256": digest, **entry,
                    } for entry in values if isinstance(entry, dict))
            dex_rate_limit_indicators.extend({
                "package_id": package_id,
                "version_code": version_code,
                "sha256": digest,
                **entry,
            } for entry in dex_analysis.get("dex_api_strings", [])
                if isinstance(entry, dict) and (
                    entry.get("rate_limit_or_retry_indicator")
                    or any(
                        "ratelimit" in header.lower() or header.lower() == "retry-after"
                        for header in entry.get("http_header_candidates", [])
                    )
                ))
            if static_analysis.get("status") == "failed":
                static_failed += 1
        else:
            static_list = []
            api_inventory = {}
            static_failed += 1

        if status.get("scan_status") == "failed":
            trufflehog_failed += 1
        verified_findings += len(trufflehog_findings)

        verification_bundle = None
        if isinstance(verification, dict):
            for item in verification.get("bundles", []):
                if (
                    item.get("package_id") == package_id
                    and str(item.get("version_code")) == version_code
                ):
                    verification_bundle = item
                    break

        artifacts.append({
            "artifact": {
                "package_id": package_id,
                "app_name": selected.get("app_name") or (acquired or {}).get("app_name", ""),
                "version_code": version_code,
                "version_name": selected.get("version_name") or (acquired or {}).get("version_name", ""),
                "sha256": digest,
                "size": int(selected.get("size") or 0),
                "source": selected.get("source", ""),
                "local_path": selected.get("local_path", ""),
                "signer_sha256": selected.get("signer_sha256", ""),
                "downloaded_at": (acquired or {}).get("downloaded_at", ""),
            },
            "acquisition": {
                "history_record_found": acquired is not None,
                "bundle_metadata_path": str(bundle_path) if bundle_path else None,
                "bundle_metadata": bundle_metadata,
                "independent_verification": verification_bundle,
            },
            "processing": {
                "apktool_status": status.get("apktool_status", "not_run"),
                "trufflehog_status": status.get("scan_status", "not_run"),
                "last_error": status.get("error", ""),
            },
            "outputs": {
                "apktool_directory": str(artifact_root / "apktool"),
                "apktool_log": str(artifact_root / "apktool.log"),
                "static_analysis_path": str(static_path) if static_analysis is not None else None,
                "trufflehog_findings_path": str(trufflehog_path) if trufflehog_path.is_file() else None,
                "trufflehog_log": str(trufflehog_dir / "trufflehog.log"),
                "trufflehog_stdout": str(trufflehog_dir / "stdout.jsonl"),
                "trufflehog_stderr": str(trufflehog_dir / "stderr.log"),
            },
            "static_analysis": static_analysis or {
                "status": "not_run",
                "findings": [],
                "coverage": {},
                "limitations": ["The static APK surface analyzer did not produce a report for this artifact."],
            },
            "findings": {
                "static_indicators": static_list,
                "trufflehog_verified_original_objects": trufflehog_findings,
            },
        })

    total_bytes = sum(int(item["artifact"]["size"]) for item in artifacts)
    payload = {
        "schema_version": 1,
        "report_type": "apkworkbench_complete_run",
        "run": {
            "run_id": run_id,
            "manifest_path": str(root / "database" / "run_manifests" / f"run_{run_id}.csv"),
            "manifest_items": len(manifest),
            "manifest_entries": manifest,
            "download_attempts": run_attempts,
            "created_for_report_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(timespec="seconds"),
        },
        "stages": {
            "acquisition": {
                "source": "Google Play",
                "status": "complete" if all(item["acquisition"]["history_record_found"] for item in artifacts) else "incomplete",
                "artifacts": len(artifacts),
                "total_manifest_bytes": total_bytes,
            },
            "independent_download_verification": verification or {"status": "missing"},
            "apktool_decompilation": {
                "complete": sum(item["processing"]["apktool_status"] == "success" for item in artifacts),
                "partial": sum(item["processing"]["apktool_status"] == "partial" for item in artifacts),
                "failed": sum(item["processing"]["apktool_status"] == "failed" for item in artifacts),
            },
            "static_apk_surface_analysis": {
                "completed": sum(item["static_analysis"].get("status") == "success" for item in artifacts),
                "partial": sum(item["static_analysis"].get("status") == "partial" for item in artifacts),
                "failed_or_missing": static_failed,
                "findings": static_findings,
                "api_endpoint_candidates": api_endpoint_count,
                "api_route_candidates": api_route_count,
                "api_smali_call_sites": len(api_call_sites),
                "androguard_external_method_references": len(dex_external_methods),
                "androguard_api_related_strings": len(dex_api_strings),
                "androguard_dex_route_candidates": sum(
                    bool(item.get("route_candidate")) for item in dex_api_strings
                ),
                "androguard_relative_path_candidates": sum(
                    bool(item.get("relative_path_candidate")) for item in dex_api_strings
                ),
                "androguard_permission_api_usage": len(dex_permission_api_usage),
                "androguard_internal_call_graph_edges": len(dex_internal_call_graph),
                "androguard_dex_rate_limit_indicators": len(dex_rate_limit_indicators),
                "client_rate_limit_retry_indicators": len(rate_limit_indicators),
                "run_record": surface_run_record or {"status": "missing_or_legacy"},
            },
            "trufflehog_verified_secret_scan": {
                "scanned": sum(item["processing"]["trufflehog_status"] == "success" for item in artifacts),
                "failed": trufflehog_failed,
                "verified_findings": verified_findings,
                "selection": "--results=verified",
            },
            "report_generation": {"status": "complete"},
            "reconciliation": reconciliation,
        },
        "api_catalog": {
            "endpoint_candidates": api_endpoints,
            "route_candidates": api_routes,
            "client_library_evidence": api_clients,
            "smali_api_call_sites": api_call_sites,
            "androguard_external_method_references": dex_external_methods,
            "androguard_api_related_strings": dex_api_strings,
            "androguard_internal_call_graph": dex_internal_call_graph,
            "androguard_permission_api_usage": dex_permission_api_usage,
            "androguard_dex_rate_limit_indicators": dex_rate_limit_indicators,
            "header_names": api_headers,
            "client_rate_limit_and_retry_indicators": rate_limit_indicators,
            "rate_limit_evidence_status": (
                "client_side_indicators_found"
                if rate_limit_indicators or dex_rate_limit_indicators
                else "no_client_side_rate_limit_indicator_found"
            ),
            "rate_limit_assessment": {
                "server_side_rate_limits": "not_determined_from_static_apk",
                "explanation": "The APK can reveal client retry/backoff logic and rate-limit headers, but cannot establish server-side quotas or whether a provider enforces a limit.",
            },
        },
        "summary": {
            "artifacts": len(artifacts),
            "verified_trufflehog_findings": verified_findings,
            "static_analysis_indicators": static_findings,
            "api_endpoint_candidates": api_endpoint_count,
            "api_route_candidates": api_route_count,
            "api_smali_call_sites": len(api_call_sites),
            "androguard_external_method_references": len(dex_external_methods),
            "androguard_api_related_strings": len(dex_api_strings),
            "androguard_dex_route_candidates": sum(
                bool(item.get("route_candidate")) for item in dex_api_strings
            ),
            "androguard_relative_path_candidates": sum(
                bool(item.get("relative_path_candidate")) for item in dex_api_strings
            ),
            "androguard_permission_api_usage": len(dex_permission_api_usage),
            "androguard_internal_call_graph_edges": len(dex_internal_call_graph),
            "androguard_dex_rate_limit_indicators": len(dex_rate_limit_indicators),
            "client_rate_limit_retry_indicators": len(rate_limit_indicators),
            "reconciliation_complete": reconciliation.get("complete", 0),
            "reconciliation_total": reconciliation.get("total", 0),
        },
        "artifacts": artifacts,
        "interpretation": {
            "trufflehog": "Complete original TruffleHog finding objects are retained in findings.trufflehog_verified_original_objects; only explicitly Verified=true records are accepted.",
            "static_analysis": "APK surface indicators are static leads with source evidence and are not equivalent to runtime-verified vulnerabilities.",
            "api_catalog": "All discovered endpoint and route candidates are included with occurrence locations. Domain strings can include non-API hostnames and require review.",
            "rate_limits": "A missing client-side rate-limit indicator does not mean the server API is unthrottled. Server-side quotas require provider documentation or authorized runtime observation.",
        },
    }

    output_dir = reports_root / "runs" / run_id
    if output_dir.is_symlink():
        raise FinalRunReportError(f"Refusing symlinked final report directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.resolve(strict=True).relative_to(reports_root.resolve(strict=True))
    json_path = output_dir / "final-report.json"
    html_path = output_dir / "final-report.html"
    _atomic_write(json_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(html_path, _html_document(payload))
    return {
        "json_path": str(json_path),
        "html_path": str(html_path),
        "artifact_count": len(artifacts),
        "verified_findings": verified_findings,
        "static_findings": static_findings,
        "api_endpoint_count": api_endpoint_count,
        "api_route_count": api_route_count,
        "api_call_site_count": len(api_call_sites),
        "androguard_external_method_count": len(dex_external_methods),
        "androguard_api_string_count": len(dex_api_strings),
        "permission_api_usage_count": len(dex_permission_api_usage),
        "internal_call_graph_edge_count": len(dex_internal_call_graph),
        "rate_limit_indicator_count": len(rate_limit_indicators) + len(dex_rate_limit_indicators),
    }
