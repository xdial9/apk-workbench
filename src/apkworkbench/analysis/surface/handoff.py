"""AI-handoff artifacts (plan v2 §5): facts.jsonl + location_map.json.

The terminal analyst is instructed (prompts/0.txt..6.txt) to read
``surface/facts.jsonl`` and ``surface/location_map.json``. Before this module
the analyzer emitted neither: facts lived only inside ``static-analysis.json``
and the location index existed only as ``workbook.location_ledger``, so an
active run would have pointed the AI at files that do not exist.

Both files are additive. No published key in ``static-analysis.json`` changes
and every fact keeps the analyzer's deterministic order. ``location_map.json``
cites the exact JSONL line of each fact, which is what the prompt chain means
by "surface/facts.jsonl line N".
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

FACTS_FILENAME = "facts.jsonl"
LOCATION_MAP_FILENAME = "location_map.json"
LOCATION_MAP_SCHEMA = 1
VALUE_PREVIEW = 160

# Analyzer evidence paths are relative to the decoded tree root, while the
# prompt chain cites folder-relative paths inside apktool/. Non-path cites
# (deduction references) use these prefixes and must not be rewritten.
TREE_ROOT_PREFIX = "apktool/"
NON_PATH_CITE_PREFIXES = (
    "sdk_root:", "permission:", "coverage:", "endpoint:", "route:", "fact:",
)


def _folder_relative(location: str) -> str:
    """Prefix tree-relative evidence with apktool/ (never rewrite absolutes)."""
    if not location or location.startswith(TREE_ROOT_PREFIX):
        return location
    if location.startswith(("/", "~")):
        return location
    if location.startswith(NON_PATH_CITE_PREFIXES):
        return location
    return TREE_ROOT_PREFIX + location



def _atomic_write_bytes(path: Path, payload: bytes) -> None:
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
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _locations(evidence: Any) -> list[str]:
    """Render evidence items as ``path:line`` strings; never invent a line."""
    locations: list[str] = []
    if isinstance(evidence, dict):
        evidence = [evidence]
    if not isinstance(evidence, list):
        return locations
    for item in evidence:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not path:
            continue
        line = item.get("line")
        location = _folder_relative(str(path))
        locations.append(f"{location}:{line}" if line else location)
    return locations


def _fact_entry(fact: dict[str, Any], line_number: int) -> dict[str, Any]:
    extra = {
        key: value
        for key, value in fact.items()
        if key not in {"kind", "value", "fingerprint", "count", "evidence",
                       "evidence_truncated"}
    }
    locations = _locations(fact.get("evidence"))
    return {
        "entry_id": f"FACT-{str(fact.get('fingerprint', ''))[:12]}",
        "source": "facts.jsonl",
        "facts_jsonl_line": line_number,
        "kind": fact.get("kind"),
        "value": str(fact.get("value"))[:VALUE_PREVIEW],
        "fingerprint": fact.get("fingerprint"),
        "occurrences": fact.get("count"),
        "has_location": bool(locations),
        "locations": locations,
        "flags": extra.get("flags") or [],
        "host_class": extra.get("host_class"),
        "how_to_verify": (
            "open the cited file(s) in apktool/ and confirm the value at the "
            "cited line; a fact is evidence, not a conclusion"
        ),
    }


def _finding_entry(finding: dict[str, Any], index: int) -> dict[str, Any]:
    evidence = finding.get("evidence")
    locations = _locations(evidence)
    context = evidence.get("context") if isinstance(evidence, dict) else None
    return {
        "entry_id": f"FINDING-{index}",
        "source": "static-analysis.json findings",
        "static_analysis_index": index,
        "rule_id": finding.get("rule_id"),
        "category": finding.get("category"),
        "confidence": finding.get("confidence"),
        "has_location": bool(locations),
        "locations": locations,
        "context": context if isinstance(context, (str, list)) else None,
        "how_to_verify": (
            "open the cited file at the cited line; the context key holds the "
            "surrounding source lines"
        ),
    }


def _deduction_entry(deduction: dict[str, Any]) -> dict[str, Any]:
    cites = [_folder_relative(str(item)) for item in (deduction.get("cites") or [])]
    return {
        "entry_id": f"DEDUCTION-{deduction.get('id')}",
        "source": "static-analysis.json deductions",
        "deduction_id": deduction.get("id"),
        "template": deduction.get("template"),
        "confidence": deduction.get("confidence"),
        "has_location": bool(cites),
        "locations": cites,
        "facts": deduction.get("facts") or [],
        "next_steps": deduction.get("next_steps") or [],
        "how_to_verify": (
            "follow the cites; each deduction is a reasoned hint over the "
            "facts named in its facts list"
        ),
    }


def build_location_map(result: dict[str, Any]) -> dict[str, Any]:
    """Index every fact, finding and deduction with its exact citation."""
    facts = result.get("facts") or []
    findings = result.get("findings") or []
    deductions = result.get("deductions") or []
    entries: list[dict[str, Any]] = []
    for line_number, fact in enumerate(facts, start=1):
        if isinstance(fact, dict):
            entries.append(_fact_entry(fact, line_number))
    for index, finding in enumerate(findings):
        if isinstance(finding, dict):
            entries.append(_finding_entry(finding, index))
    for deduction in deductions:
        if isinstance(deduction, dict):
            entries.append(_deduction_entry(deduction))
    return {
        "schema_version": LOCATION_MAP_SCHEMA,
        "artifact": result.get("artifact") or {},
        "analyzer": result.get("analyzer") or {},
        "status": result.get("status"),
        "counts": {
            "facts": len(facts),
            "findings": len(findings),
            "deductions": len(deductions),
            "entries": len(entries),
        },
        "sources": {
            "static-analysis.json": [
                "facts", "findings", "deductions", "coverage", "manifest",
                "inventory", "metrics", "workbook",
            ],
            FACTS_FILENAME: (
                "one JSON object per line; line N is cited by "
                "entries[].facts_jsonl_line"
            ),
            LOCATION_MAP_FILENAME: "this index (generated, deterministic)",
        },
        "entries": entries,
    }


def write_handoff(directory: str | Path, result: dict[str, Any]) -> dict[str, Path]:
    """Write facts.jsonl + location_map.json into ``directory`` atomically.

    Returns the two paths. Both files are rewritten wholesale so a rerun can
    never append duplicate facts.
    """
    target_dir = Path(directory)
    facts_path = target_dir / FACTS_FILENAME
    location_map_path = target_dir / LOCATION_MAP_FILENAME

    facts = [fact for fact in (result.get("facts") or []) if isinstance(fact, dict)]
    stream = "".join(
        json.dumps(fact, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for fact in facts
    )
    _atomic_write_bytes(facts_path, stream.encode("utf-8"))

    payload = build_location_map(result)
    _atomic_write_bytes(
        location_map_path,
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return {"facts": facts_path, "location_map": location_map_path}
