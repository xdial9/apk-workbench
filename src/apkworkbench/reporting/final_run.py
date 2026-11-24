"""One consolidated evidence package for a complete APK Workbench run."""
from __future__ import annotations

from datetime import datetime, timezone
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


def _read_jsonl(
    path: Path,
    root: Path,
    *,
    native_only: bool = False,
) -> list[dict[str, Any]] | None:
    if path.is_symlink():
        raise FinalRunReportError(f"Refusing symlinked report input: {path}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise FinalRunReportError(f"Cannot resolve run evidence {path}: {exc}") from exc
    records: list[dict[str, Any]] = []
    try:
        with resolved.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise FinalRunReportError(
                        f"Malformed JSONL evidence {path}:{line_number}: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise FinalRunReportError(
                        f"Expected a JSON object in {path}:{line_number}."
                    )
                if native_only:
                    edge_types = {"method->native", "native->secret"}
                    chain_edges = value.get("edges")
                    is_native = value.get("edge_type") in edge_types or (
                        isinstance(chain_edges, list)
                        and any(
                            isinstance(edge, dict)
                            and edge.get("edge_type") in edge_types
                            for edge in chain_edges
                        )
                    )
                    if not is_native:
                        continue
                records.append(value)
    except OSError as exc:
        raise FinalRunReportError(f"Cannot read run evidence {path}: {exc}") from exc
    return records


def _native_evidence(
    static_analysis: dict[str, Any] | None,
    trace_chains: list[dict[str, Any]] | None,
    links: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if not isinstance(static_analysis, dict):
        return {
            "status": "not_run",
            "coverage": {},
            "metrics": {},
            "libraries": [],
            "jni_entries": [],
            "jni_unmapped": [],
            "exports": [],
            "imports": [],
            "export_records_total": 0,
            "import_records_total": 0,
            "dynamic_registration_candidates": [],
            "links": [],
            "links_status": "not_run",
            "trace_chains": [],
            "trace_chains_status": "not_run",
        }

    coverage = static_analysis.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    native_coverage = coverage.get("native_libraries")
    if static_analysis.get("status") == "failed":
        status = "failed"
    elif native_coverage == "not_found":
        status = "not_present"
    elif native_coverage is None:
        status = "not_run"
    else:
        status = str(native_coverage)

    inventory = static_analysis.get("inventory")
    inventory = inventory if isinstance(inventory, dict) else {}
    libraries = inventory.get("native_analysis")
    libraries = libraries if isinstance(libraries, list) else []
    entries = inventory.get("jni_entries")
    entries = entries if isinstance(entries, list) else []
    unmapped = inventory.get("jni_unmapped")
    unmapped = unmapped if isinstance(unmapped, list) else []
    facts = static_analysis.get("facts")
    facts = facts if isinstance(facts, list) else []
    dynamic_candidates = [
        fact for fact in facts
        if isinstance(fact, dict)
        and fact.get("kind") == "native_jni_register_natives_candidate"
    ]
    exports = [
        fact for fact in facts
        if isinstance(fact, dict) and fact.get("kind") == "native_export"
    ]
    imports = [
        fact for fact in facts
        if isinstance(fact, dict) and fact.get("kind") == "native_import"
    ]
    native_traces = [
        chain for chain in (trace_chains or [])
        if any(
            isinstance(edge, dict)
            and edge.get("edge_type") in {"method->native", "native->secret"}
            for edge in chain.get("edges", [])
        )
    ]
    native_links = [
        edge for edge in (links or [])
        if edge.get("edge_type") in {"method->native", "native->secret"}
    ]
    return {
        "status": status,
        "coverage": {
            key: value for key, value in coverage.items()
            if isinstance(key, str) and key.startswith("native_")
        },
        "metrics": (
            static_analysis.get("metrics")
            if isinstance(static_analysis.get("metrics"), dict) else {}
        ),
        "libraries": libraries,
        "jni_entries": entries,
        "jni_unmapped": unmapped,
        "exports": exports[:100],
        "imports": imports[:100],
        "export_records_total": len(exports),
        "import_records_total": len(imports),
        "dynamic_registration_candidates": dynamic_candidates,
        "links": native_links,
        "links_status": "available" if links is not None else "missing",
        "trace_chains": native_traces,
        "trace_chains_status": (
            "available" if trace_chains is not None else "missing"
        ),
    }


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


def _native_html_section(native: dict[str, Any]) -> list[str]:
    metrics = native.get("metrics", {})
    metrics = metrics if isinstance(metrics, dict) else {}
    libraries = native.get("libraries", [])
    entries = native.get("jni_entries", [])
    unmapped = native.get("jni_unmapped", [])
    dynamic_candidates = native.get("dynamic_registration_candidates", [])
    status = str(native.get("status", "not_run"))

    def metric(name: str) -> str:
        value = metrics.get(name)
        return "unavailable" if value is None else str(value)

    parts = [
        "<h4>Native analysis</h4>",
        (
            f"<p>Status: {html.escape(status)} · "
            f"Libraries: {metric('native_library_count')} · "
            f"JNI exports: {metric('native_jni_exports_total')} "
            f"({metric('native_jni_exports_mapped')} mapped, "
            f"{metric('native_jni_exports_unmapped')} unmapped) · "
            f"Imports: {metric('native_imports_total')} total / "
            f"{metric('native_imports_emitted')} emitted</p>"
        ),
        (
            f"<p>Native strings: {metric('native_strings_total')} total · "
            f"{metric('native_strings_emitted')} emitted · "
            f"{metric('native_strings_sharded')} sharded · "
            f"{metric('native_strings_dropped')} dropped · "
            f"coverage: {html.escape(str(native.get('coverage', {}).get('native_strings', 'unavailable')))}</p>"
        ),
    ]
    if status == "not_present":
        parts.append("<p>No native libraries were present in the decoded artifact.</p>")
    elif status == "not_run":
        parts.append("<p>Native analysis was not run or its status is unavailable.</p>")
    elif status == "failed":
        parts.append("<p>Native analysis failed; inspect the retained diagnostics.</p>")

    if libraries:
        parts.append(
            "<details open><summary>Native library inventory</summary>"
            "<table><thead><tr><th>Library</th><th>Parse state / reason</th>"
            "<th>Exports</th><th>Imports</th><th>JNI mapped / unmapped</th>"
            "<th>Load state</th><th>Strings</th></tr></thead><tbody>"
        )
        for library in libraries:
            if not isinstance(library, dict):
                continue
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(library.get('path', 'unknown')))}</code></td>"
                f"<td>{html.escape(str(library.get('state', 'unknown')))}"
                f"{': ' + html.escape(str(library.get('reason'))) if library.get('reason') else ''}</td>"
                f"<td>{html.escape(str(library.get('exports_total', 'unavailable')))} "
                f"({html.escape(str(library.get('exports_emitted', 'unavailable')))} emitted)</td>"
                f"<td>{html.escape(str(library.get('imports_total', 'unavailable')))} "
                f"({html.escape(str(library.get('imports_emitted', 'unavailable')))} emitted)</td>"
                f"<td>{html.escape(str(library.get('jni_entries', 'unavailable')))} / "
                f"{html.escape(str(library.get('jni_unmapped', 'unavailable')))}</td>"
                f"<td>{html.escape(str(library.get('load_status', 'unavailable')))}"
                f"{': ' + html.escape(str(library.get('load_reason'))) if library.get('load_reason') else ''}</td>"
                f"<td>{html.escape(str(library.get('strings_unique', 'unavailable')))} unique"
                f"{' (truncated)' if library.get('strings_truncated') else ''}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></details>")
    elif status not in {"not_present", "not_run"}:
        parts.append("<p>No per-library records were emitted; review native coverage and diagnostics.</p>")

    if entries:
        parts.append(
            "<details open><summary>JNI exports mapped to Java methods</summary>"
            "<table><thead><tr><th>Native library</th><th>Java method</th>"
            "<th>Smali citation</th><th>Mapping basis</th></tr></thead><tbody>"
        )
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(str(entry.get('library', 'unknown')))}</code></td>"
                f"<td><code>{html.escape(str(entry.get('java_class', 'unknown')))}."
                f"{html.escape(str(entry.get('java_method', 'unknown')))}"
                f"{html.escape(str(entry.get('java_signature', '')))}</code></td>"
                f"<td><code>{html.escape(str(entry.get('smali_path', 'unknown')))}:"
                f"{html.escape(str(entry.get('smali_line', '')))}</code></td>"
                f"<td>{html.escape(str(entry.get('confidence', 'unavailable')))}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></details>")

    for label, key, total_key in (
        ("Native exports", "exports", "export_records_total"),
        ("Native imports", "imports", "import_records_total"),
    ):
        records = native.get(key, [])
        if records:
            parts.append(
                f"<details><summary>{label}: "
                f"{html.escape(str(native.get(total_key, len(records))))} emitted "
                f"(showing up to {len(records)})</summary><ul>"
            )
            for record in records:
                evidence = record.get("evidence")
                evidence = evidence if isinstance(evidence, dict) else {}
                parts.append(
                    f"<li><code>{html.escape(str(record.get('value', 'unknown')))}</code> "
                    f"— {html.escape(str(evidence.get('path', 'unknown')))}"
                    f"@0x{int(evidence.get('offset') or 0):x}</li>"
                )
            parts.append("</ul></details>")

    def cite(citation: dict[str, Any]) -> str:
        value = str(citation.get("source_path") or citation.get("evidence_kind") or "unknown")
        if citation.get("line_start") is not None:
            value += f":{citation['line_start']}"
        if citation.get("byte_offset_start") is not None:
            value += f"@0x{int(citation['byte_offset_start']):x}"
        return html.escape(value)

    unresolved: list[str] = []
    for entry in unmapped:
        if not isinstance(entry, dict):
            continue
        location = f"{entry.get('library', 'unknown')}@0x{int(entry.get('offset') or 0):x}"
        unresolved.append(
            f"<li>Unmapped JNI export <code>{html.escape(str(entry.get('symbol', 'unknown')))}</code> "
            f"({html.escape(str(entry.get('reason', 'reason unavailable')))}; "
            f"{html.escape(location)})</li>"
        )
    for fact in dynamic_candidates:
        if not isinstance(fact, dict):
            continue
        evidence = fact.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        extra = fact.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        location = f"{evidence.get('path', fact.get('value', 'unknown'))}@0x{int(evidence.get('offset') or 0):x}"
        unresolved.append(
            f"<li>Dynamic JNI registration candidate in "
            f"<code>{html.escape(str(fact.get('value', 'unknown')))}</code>: "
            f"{html.escape(str(extra.get('reason', 'pairing unresolved')))} "
            f"({html.escape(location)})</li>"
        )
    for library in libraries:
        if not isinstance(library, dict):
            continue
        if library.get("load_sites"):
            continue
        unresolved.append(
            f"<li>No load site for <code>{html.escape(str(library.get('path', 'unknown')))}</code>: "
            f"{html.escape(str(library.get('load_reason') or library.get('load_status') or 'reason unavailable'))}</li>"
        )
    if status == "not_present":
        unresolved.append("<li>No native libraries were present.</li>")
    if unresolved:
        parts.append("<h5>Unresolved native evidence</h5><ul>")
        parts.extend(unresolved)
        parts.append("</ul>")

    native_links = native.get("links", [])
    if native_links:
        parts.append("<details><summary>JNI and native-secret links with citations</summary><ul>")
        for edge in native_links:
            citations = edge.get("citations", [])
            locations = ", ".join(
                cite(item) for item in citations if isinstance(item, dict)
            )
            parts.append(
                f"<li>{html.escape(str(edge.get('edge_type', 'native link')))} "
                f"— {locations or 'citation unavailable'}</li>"
            )
        parts.append("</ul></details>")
    else:
        parts.append(
            f"<p>Native link records: {html.escape(str(native.get('links_status', 'unavailable')))}.</p>"
        )

    chains = native.get("trace_chains", [])
    parts.append(
        f"<h5>JNI/secret trace chains ({len(chains)})</h5>"
    )
    if chains:
        parts.append("<ol>")
        for chain in chains:
            edge_types: list[str] = []
            citations: list[str] = []
            for edge in chain.get("edges", []):
                if not isinstance(edge, dict):
                    continue
                edge_types.append(str(edge.get("edge_type", "unknown")))
                for item in edge.get("citations", []):
                    if isinstance(item, dict):
                        citations.append(cite(item))
            parts.append(
                f"<li>{html.escape(' → '.join(edge_types))}"
                f"<br><span class='muted'>{', '.join(citations) or 'citations unavailable'}</span></li>"
            )
        parts.append("</ol>")
    else:
        parts.append(
            f"<p>No native trace chains; trace data status: "
            f"{html.escape(str(native.get('trace_chains_status', 'unavailable')))}.</p>"
        )
    return parts


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
            locations = item.get("evidence") or []
            evidence = "; ".join(
                f"{html.escape(str(loc.get('path', '')))}:{html.escape(str(loc.get('line', '')))}"
                for loc in locations
                if isinstance(loc, dict)
            )
            nearby = item.get("nearby_rate_limit_indicators") or []
            signal_text = "; ".join(
                f"{html.escape(str(sig.get('path', '')))}:{html.escape(str(sig.get('line', '')))}"
                for sig in nearby
                if isinstance(sig, dict)
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
                for loc in (item.get("evidence") or [])
                if isinstance(loc, dict)
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
    dex_call_graph = api_catalog.get("androguard_internal_call_graph", [])
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
    for artifact in payload.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        metadata = artifact.get("artifact") if isinstance(artifact.get("artifact"), dict) else {}
        static = artifact.get("static_analysis") if isinstance(artifact.get("static_analysis"), dict) else {}
        findings = artifact.get("findings") if isinstance(artifact.get("findings"), dict) else {}
        static_items = findings.get("static_indicators") or []
        verified_items = findings.get("trufflehog_verified_original_objects") or []
        parts.append(
            f"<h3>{html.escape(str(metadata.get('package_id', 'unknown')))} "
            f"v{html.escape(str(metadata.get('version_code', 'unknown')))} "
            f"— {html.escape(str(metadata.get('sha256', '')))}</h3>"
        )
        dex = static.get("dex_analysis", {})
        if isinstance(dex, dict):
            metrics = dex.get("metrics") if isinstance(dex.get("metrics"), dict) else {}
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
        native_ev = artifact.get("native_evidence")
        parts.extend(_native_html_section(native_ev if isinstance(native_ev, dict) else {}))
        parts.append("<h4>Static-analysis coverage</h4>")
        coverage = static.get("coverage")
        if isinstance(coverage, dict) and coverage:
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
                if not isinstance(finding, dict):
                    continue
                raw_ev = finding.get("evidence")
                evidence = raw_ev if isinstance(raw_ev, dict) else {}
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
    unverified_findings_retained = 0
    static_findings = 0
    api_endpoint_count = 0
    api_route_count = 0
    static_failed = 0
    trufflehog_failed = 0
    native_files_found = 0
    native_jni_exports_total = 0
    native_jni_exports_mapped = 0
    native_jni_exports_unmapped = 0
    native_strings_total = 0
    native_strings_emitted = 0
    native_strings_sharded = 0
    native_strings_dropped = 0

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
        if bundle_metadata is None:
            manifest_bundle_path = results_root / package_id / version_code / digest / "manifest" / "google-play-bundle.json"
            bundle_metadata = _read_json(manifest_bundle_path, results_root)
            if bundle_metadata is not None:
                bundle_path = manifest_bundle_path

        artifact_root = results_root / package_id / version_code / digest
        # D-3: try the new surface/ path first; fall back to legacy root for backward
        # compatibility. A test validates BOTH paths resolve correctly.
        surface_dir = artifact_root / "surface"
        static_path = surface_dir / "static-analysis.json"
        legacy_static_path = artifact_root / "static-analysis.json"
        static_analysis = _read_json(static_path, results_root) or _read_json(legacy_static_path, results_root)
        if static_analysis is None:
            # Surface analysis only runs against decoded Apktool output. When
            # decompilation produced no usable output, the artifact is legitimately
            # skipped (no ``apktool/`` directory to sweep), so a missing
            # static-analysis.json is expected rather than a fatal inconsistency.
            # A genuine "successful analysis without a result" still raises.
            apktool_state = status.get("apktool_status", "not_run")
            if apktool_state in {"success", "partial"}:
                raise FinalRunReportError(
                    f"Surface analysis succeeded for {package_id} but the expected "
                    f"static-analysis.json is missing from either {static_path} or {legacy_static_path}."
                )
        trufflehog_dir = artifact_root / "trufflehog"
        trufflehog_path = trufflehog_dir / "findings.json"
        trufflehog_unverified_count = 0
        if status.get("scan_status") == "success":
            all_trufflehog_findings = _read_json(trufflehog_path, results_root)
            if all_trufflehog_findings is None:
                raise FinalRunReportError(
                    f"TruffleHog status says success but findings.json is missing for {package_id}."
                )
            if not isinstance(all_trufflehog_findings, list) or any(
                not isinstance(item, dict) for item in all_trufflehog_findings
            ):
                raise FinalRunReportError(
                    f"TruffleHog evidence for {package_id} is malformed."
                )
            # Report plane stays verified-only; unverified records are retained
            # in the trufflehog/ handoff files and counted, never dropped.
            trufflehog_findings = [
                item for item in all_trufflehog_findings if item.get("Verified") is True
            ]
            trufflehog_unverified_count = len(all_trufflehog_findings) - len(trufflehog_findings)
        else:
            # Never present an older findings file as the result of a failed or unrun scan.
            trufflehog_findings = []

        if isinstance(static_analysis, dict):
            static_list = static_analysis.get("findings", [])
            if not isinstance(static_list, list):
                static_list = []
            static_findings += len(static_list)
            # Native plane counters: a mapped JNI surface is a fact about the
            # artifact, so the run report must be able to prove it happened.
            native_metrics = static_analysis.get("metrics", {})
            if isinstance(native_metrics, dict):
                native_files_found += int(native_metrics.get("native_files_found") or 0)
                native_jni_exports_total += int(native_metrics.get("native_jni_exports_total") or 0)
                native_jni_exports_mapped += int(native_metrics.get("native_jni_exports_mapped") or 0)
                native_jni_exports_unmapped += int(native_metrics.get("native_jni_exports_unmapped") or 0)
                native_strings_total += int(native_metrics.get("native_strings_total") or 0)
                native_strings_emitted += int(native_metrics.get("native_strings_emitted") or 0)
                native_strings_sharded += int(native_metrics.get("native_strings_sharded") or 0)
                native_strings_dropped += int(native_metrics.get("native_strings_dropped") or 0)
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
            } for entry in (dex_analysis.get("dex_api_strings") or [])
                if isinstance(entry, dict) and (
                    entry.get("rate_limit_or_retry_indicator")
                    or any(
                        isinstance(header, str)
                        and ("ratelimit" in header.lower() or header.lower() == "retry-after")
                        for header in (entry.get("http_header_candidates") or [])
                    )
                ))
            if static_analysis.get("status") == "failed":
                static_failed += 1
        else:
            static_list = []
            api_inventory = {}
            static_failed += 1

        surface_trace_path = surface_dir / "trace_chains.jsonl"
        legacy_trace_path = artifact_root / "trace_chains.jsonl"
        native_trace_path = (
            surface_trace_path
            if surface_trace_path.is_file() or surface_trace_path.is_symlink()
            else legacy_trace_path
        )
        surface_links_path = surface_dir / "links.jsonl"
        legacy_links_path = artifact_root / "links.jsonl"
        native_links_path = (
            surface_links_path
            if surface_links_path.is_file() or surface_links_path.is_symlink()
            else legacy_links_path
        )
        native_evidence = _native_evidence(
            static_analysis if isinstance(static_analysis, dict) else None,
            _read_jsonl(native_trace_path, results_root, native_only=True),
            _read_jsonl(native_links_path, results_root, native_only=True),
        )

        if status.get("scan_status") == "failed":
            trufflehog_failed += 1
        verified_findings += len(trufflehog_findings)
        unverified_findings_retained += trufflehog_unverified_count

        verification_bundle = None
        if isinstance(verification, dict):
            for item in verification.get("bundles") or []:
                if (
                    isinstance(item, dict)
                    and item.get("package_id") == package_id
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
                "trufflehog_verified_text": (
                    str(trufflehog_dir / "findings-verified.txt")
                    if (trufflehog_dir / "findings-verified.txt").is_file() else None
                ),
                "trufflehog_unverified_findings_path": (
                    str(trufflehog_dir / "findings-unverified.json")
                    if (trufflehog_dir / "findings-unverified.json").is_file() else None
                ),
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
            "native_evidence": native_evidence,
            "findings": {
                "static_indicators": static_list,
                "trufflehog_verified_original_objects": trufflehog_findings,
                "trufflehog_unverified_count": trufflehog_unverified_count,
                "trufflehog_verified_text": (
                    str(trufflehog_dir / "findings-verified.txt")
                    if (trufflehog_dir / "findings-verified.txt").is_file() else None
                ),
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
            "created_for_report_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
                "native_files_found": native_files_found,
                "native_jni_exports_total": native_jni_exports_total,
                "native_jni_exports_mapped": native_jni_exports_mapped,
                "native_jni_exports_unmapped": native_jni_exports_unmapped,
                "native_jni_mapping_complete": (
                    native_jni_exports_total
                    == native_jni_exports_mapped + native_jni_exports_unmapped
                ),
                "native_strings_total": native_strings_total,
                "native_strings_emitted": native_strings_emitted,
                "native_strings_sharded": native_strings_sharded,
                "native_strings_dropped": native_strings_dropped,
                "run_record": surface_run_record or {"status": "missing_or_legacy"},
            },
            "trufflehog_verified_secret_scan": {
                "scanned": sum(item["processing"]["trufflehog_status"] == "success" for item in artifacts),
                "failed": trufflehog_failed,
                "verified_findings": verified_findings,
                "unverified_findings_retained": unverified_findings_retained,
                "selection": "--results=<complete set> (verified reported; unverified preserved in trufflehog/ for the AI handoff)",
                "verified_text_reports": [
                    item["findings"]["trufflehog_verified_text"]
                    for item in artifacts
                    if item["findings"].get("trufflehog_verified_text")
                ],
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
            "unverified_trufflehog_findings_retained": unverified_findings_retained,
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
            "trufflehog": "Complete original TruffleHog finding objects are retained in findings.trufflehog_verified_original_objects; only explicitly Verified=true records are reported. Unverified findings are counted and kept in trufflehog/findings-unverified.json for the AI handoff. findings-verified.txt is the human-facing verified-only summary.",
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
