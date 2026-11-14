"""WORKBOOK builder (plan v2 §7A / P10) — the active-agent handoff section.

The workbook turns the analyzer's data plane into a work assignment the
terminal AI can execute: mission + laws, a location ledger (every entry
with folder-relative file:line cites), the permission map (immutable
evidence vs writable overlay), the investigation playbook (open leads
derived from deductions and coverage gaps — nothing invented), and the
finish line. Model-agnostic: plain JSON, self-describing, no external
context required.
"""
from __future__ import annotations

from typing import Any

MISSION = (
    "You are the final analysis stage of a deterministic static-analysis "
    "pipeline. Your job: (1) map the raw decompiled application tree "
    "yourself BEFORE relying on tool conclusions; (2) read this output; "
    "(3) trace every open lead below, decoding and correlating as needed; "
    "(4) record your own findings in the working area with citations; "
    "(5) close every coverage item or explain why it stays open. You are "
    "an analyst extending the work, not a reader summarizing it."
)

LAWS = (
    "Deduce from data, never guess: every claim cites folder-relative "
    "evidence (file:line) or is labeled an open question. Similarity is a "
    "hint, never a link. Nothing is hidden: coverage entries named here are "
    "the complete truth of what was and was not analyzed."
)

CONFIDENCE_LABELS = ["tool_verified", "deduced", "hint", "open_question", "ai_deduced"]

IMMUTABLE_EVIDENCE = [
    "apktool/ (decoded application tree)",
    "surface/static-analysis.json + surface/facts.jsonl (tool output)",
    "trufflehog/ (verified secret findings)",
    "manifest/ + google-play-bundle.json (acquisition provenance)",
]

WORKING_AREA = "ai_analysis/"

DELIVERABLES = [
    "ai_analysis/dossier.md",
    "ai_analysis/ai_analysis.json",
    "ai_analysis/lead_ledger.json",
    "ai_analysis/closure_report.md",
    "ai_analysis/memory/ (scratch — internal only)",
]

FINISH_LINE = {
    "definition": (
        "Every lead below is pursued or dismissed with a reason; every "
        "coverage entry is expanded by your own work or marked unknown with "
        "an honest reason; deliverables written with citations; the corpus "
        "files are byte-identical to arrival."
    ),
    "checklist": [
        "all leads triaged (lead_ledger.json complete)",
        "all coverage gaps addressed or explained",
        "dossier.md + ai_analysis.json + closure_report.md written",
        "every AI claim cites folder-relative evidence",
    ],
}


def _fact_locations(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for fact in facts:
        evidence = fact.get("evidence") or []
        locations = [
            f"{item.get('path', '')}:{item.get('line')}" if item.get("line")
            else str(item.get("path", ""))
            for item in evidence
        ]
        if not locations:
            continue
        entries.append({
            "kind": fact.get("kind"),
            "value": str(fact.get("value"))[:160],
            "fingerprint": fact.get("fingerprint"),
            "occurrences": fact.get("count"),
            "locations": locations,
            "how_to_verify": "open the cited file(s); recompute hashes by streaming the file",
        })
    return entries


def _finding_locations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        evidence = finding.get("evidence") or {}
        path = evidence.get("path") or ""
        line = evidence.get("line")
        if not path:
            continue
        entries.append({
            "kind": "finding",
            "rule_id": finding.get("rule_id"),
            "index": index,
            "location": f"{path}:{line}" if line else path,
            "confidence": finding.get("confidence"),
            "how_to_verify": "open the cited file at the cited line; context key holds +/-2 lines",
        })
    return entries


def _deduction_leads(deductions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    leads: list[dict[str, Any]] = []
    for deduction in deductions:
        leads.append({
            "id": deduction.get("id"),
            "title": str(deduction.get("narrative"))[:200],
            "priority": "high" if deduction.get("confidence") == "hint" else "normal",
            "suggested_method": deduction.get("next_steps") or [],
            "cites": deduction.get("cites") or [],
            "source": "deduction",
        })
    return leads


def _coverage_leads(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    done = {"success", "complete", "not_applicable"}
    leads: list[dict[str, Any]] = []
    for area, status in sorted(coverage.items()):
        if status in done:
            continue
        leads.append({
            "id": f"COV-{area}",
            "title": f"Coverage gap: {area} = {status}",
            "priority": "normal" if status.startswith("not_") else "high",
            "suggested_method": [
                (
                    "Investigate this area directly in the raw tree; expand "
                    "the analysis or close it with an honest reason in the "
                    "closure report."
                ),
            ],
            "cites": [f"coverage:{area}"],
            "source": "coverage",
        })
    return leads


def _flagged_fact_leads(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    leads: list[dict[str, Any]] = []
    for fact in facts:
        extra = {k: v for k, v in fact.items() if k not in {
            "kind", "value", "fingerprint", "count", "evidence",
            "evidence_truncated",
        }}
        flags = extra.pop("flags", None) or []
        interesting = (
            "userinfo" in flags
            or extra.get("host_class") in {"private", "idn", "reserved"}
            or fact.get("kind") == "decoded_string"
        )
        if not interesting:
            continue
        locations = [
            f"{item.get('path', '')}:{item.get('line')}" if item.get("line")
            else str(item.get("path", ""))
            for item in (fact.get("evidence") or [])
        ]
        leads.append({
            "id": f"FACT-{fact.get('fingerprint', '')[:12]}",
            "title": f"Flagged fact ({fact.get('kind')}): {str(fact.get('value'))[:120]}",
            "priority": "normal",
            "suggested_method": [
                (
                    "Verify this in the raw tree; decide whether it is app "
                    "behavior, an SDK artifact, or tooling noise; record "
                    "the outcome with citations."
                ),
            ],
            "cites": locations,
            "source": "flagged_fact",
        })
    return leads


def build_workbook(result: dict[str, Any]) -> dict[str, Any]:
    facts = result.get("facts") or []
    deductions = result.get("deductions") or []
    findings = result.get("findings") or []
    coverage = result.get("coverage") or {}
    open_leads = (
        _deduction_leads(deductions)
        + _coverage_leads(coverage)
        + _flagged_fact_leads(facts)
    )
    return {
        "schema_version": 1,
        "mission": MISSION,
        "laws": LAWS,
        "confidence_labels": CONFIDENCE_LABELS,
        "permission_map": {
            "immutable_evidence": IMMUTABLE_EVIDENCE,
            "working_area": WORKING_AREA,
            "deliverables": DELIVERABLES,
        },
        "location_ledger": {
            "facts": _fact_locations(facts),
            "findings": _finding_locations(findings),
            "deductions": [
                {
                    "id": deduction.get("id"),
                    "template": deduction.get("template"),
                    "cites": deduction.get("cites") or [],
                    "facts": deduction.get("facts") or [],
                }
                for deduction in deductions
            ],
            "tool_outputs": [
                "surface/static-analysis.json — summary sections (this file)",
                "surface/facts.jsonl — full streamed facts (when present)",
                "trufflehog/ — verified secret findings (evidence-grade)",
                "google-play-bundle.json — acquisition provenance + hashes",
            ],
        },
        "playbook": {
            "open_leads": open_leads,
            "note": (
                "The numbered instruction chain (1.txt..) walks the full "
                "workflow; this playbook is the generated per-artifact lead "
                "set it consumes."
            ),
        },
        "finish_line": FINISH_LINE,
    }