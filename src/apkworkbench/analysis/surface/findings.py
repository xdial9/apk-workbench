"""Shared finding builder for surface analyzers (no import cycles).

Findings carry the established shape: analyzer id "apk-surface", evidence
with path/line/snippet, confidence, verification_state. Never redact: the
caller decides how much context the snippet carries; the dossier keeps
what it is given.
"""
from __future__ import annotations

from typing import Any

ANALYZER_ID = "apk-surface"


def build_finding(
    rule_id: str,
    category: str,
    severity: str,
    title: str,
    message: str,
    path: str,
    line: int | None,
    snippet: str,
    confidence: float,
) -> dict[str, Any]:
    return {
        "analyzer": ANALYZER_ID,
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "verification_state": "static_unverified",
        "title": title,
        "message": message,
        "evidence": {"path": path, "line": line, "snippet": snippet},
    }