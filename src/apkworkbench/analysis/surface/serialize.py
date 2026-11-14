"""Final assembly for per-artifact surface output (plan v2 §5/S6).

Adds the handoff plane (workbook) and honest metrics (raw vs distinct)
without touching consumer-established keys (appdev.txt §15).
"""
from __future__ import annotations

from typing import Any

from apkworkbench.analysis.surface.workbook import build_workbook


def finalize_result(result: dict[str, Any]) -> dict[str, Any]:
    findings = result.get("findings") or []
    distinct = {
        (
            finding.get("rule_id"),
            (finding.get("evidence") or {}).get("path"),
            (finding.get("evidence") or {}).get("line"),
        )
        for finding in findings
    }
    metrics = result.setdefault("metrics", {})
    metrics["distinct_finding_count"] = len(distinct)
    metrics["fact_count"] = len(result.get("facts") or [])
    metrics["deduction_count"] = len(result.get("deductions") or [])
    result["workbook"] = build_workbook(result)
    return result