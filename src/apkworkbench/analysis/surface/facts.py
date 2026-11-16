"""Fingerprint fact store (plan v2 S5) — dedup law implementation.

Fact = (kind, normalized value, fingerprint, evidence, count). Identical
fingerprints merge; evidence is NOT capped — all evidence retained for AI
 handoff (plan §8B: dense, deduped, pointerized). Counts stay exact.
CAP-FREE: was capped at 3 representative evidence items, which hid evidence from AI.
"""
from __future__ import annotations

import hashlib
from typing import Any

# CAP-FREE: REPRESENTATIVE_EVIDENCE_CAP deleted. No evidence cap. All evidence retained.
# Kept as alias for backwards compat imports, but not used to truncate.
REPRESENTATIVE_EVIDENCE_CAP = None  # deprecated, do not use to truncate


# Keys owned by the fact record itself. `extra` may add fields, never replace
# these: a caller that passes `extra={"value": ...}` used to overwrite the
# fact's own value and silently corrupt the plane (it happened twice).
RESERVED_FACT_KEYS = frozenset({"kind", "value", "fingerprint", "count", "evidence"})


def fingerprint(value: Any) -> str:
    normalized = str(value).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class FactStore:
    def __init__(self, *, evidence_cap: int | None = None):
        # CAP-FREE: evidence_cap param kept for compat, ignored. No truncation.
        self._by_key: dict[tuple[str, str], dict[str, Any]] = {}
        self._evidence_cap = None

    def add(
        self,
        kind: str,
        value: Any,
        evidence: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        if extra:
            collisions = RESERVED_FACT_KEYS.intersection(extra)
            if collisions:
                raise ValueError(
                    f"extra may not overwrite fact keys: {sorted(collisions)}"
                )
        fp = fingerprint(value)
        key = (kind, fp)
        record = self._by_key.get(key)
        if record is None:
            record = {
                "kind": kind,
                "value": value,
                "fingerprint": fp,
                "count": 0,
                "evidence": [],
            }
            if extra:
                record.update(extra)
            self._by_key[key] = record
        record["count"] += 1
        if evidence:
            # A call site may supply one evidence item or a whole list (a JNI
            # entry cites both the symbol record and the smali declaration).
            # Both land as individual evidence items, never as a nested list.
            if isinstance(evidence, list):
                record["evidence"].extend(item for item in evidence if item)
            else:
                record["evidence"].append(evidence)
        return fp

    def fingerprints(self, kind: str | None = None) -> list[str]:
        return [
            record["fingerprint"] for key, record in self._by_key.items()
            if kind is None or key[0] == kind
        ]

    def values(self, kind: str) -> list[Any]:
        return [
            record["value"] for key, record in self._by_key.items() if key[0] == kind
        ]

    def records(self, kind: str | None = None) -> list[dict[str, Any]]:
        chosen = [
            record for key, record in self._by_key.items()
            if kind is None or key[0] == kind
        ]
        chosen.sort(key=lambda record: (record["kind"], record["fingerprint"]))
        return chosen

    def export(self) -> list[dict[str, Any]]:
        """Sorted, FULL-evidence export (machine plane; AI handoff shape)."""
        exported: list[dict[str, Any]] = []
        for record in self.records():
            entry = dict(record)
            # CAP-FREE: was capped at 3 evidence items, evidence_truncated=True if over 3. Now keep ALL evidence.
            entry["evidence"] = list(record["evidence"])
            entry["evidence_truncated"] = False
            entry["evidence_count"] = len(record["evidence"])
            exported.append(entry)
        return exported

    def __len__(self) -> int:
        return len(self._by_key)


def package_root_histogram(
    tree_entries: list[Any],
    app_package: str | None,
) -> dict[str, dict[str, Any]]:
    """Data-driven third-party SDK detection (appdev.txt §3): package ROOT
    histogram from smali paths; known-platform roots excluded by evidence
    (android/, androidx/, kotlin/, java/...), app-owned root identified from
    the manifest package. Never guessed: roots come from observed paths."""
    platform_first_segments = {"android", "androidx", "kotlin", "kotlinx", "java", "javax"}
    known_platform_roots = {
        "com/google", "com/google/android", "org/apache", "org/json",
        "org/intellij", "org/jetbrains",
    }
    counts: dict[str, int] = {}
    first_path: dict[str, str] = {}
    for entry in tree_entries:
        relative = entry.relative
        if not relative.startswith("smali"):
            continue
        parts = relative.split("/")
        # smali|smali_classes2/<root segments up to 3>/<Class>.smali
        if not (parts and parts[0].startswith("smali")):
            continue
        if len(parts) < 4 or not parts[-1].endswith(".smali"):
            continue
        root = "/".join(parts[1:-1][:3])
        counts[root] = counts.get(root, 0) + 1
        if root not in first_path:
            first_path[root] = relative
    app_roots: set[str] = set()
    if app_package:
        app_roots.add(app_package.replace(".", "/"))
    histogram: dict[str, dict[str, Any]] = {}
    for root, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        first_segments = root.split("/")
        two = "/".join(first_segments[:2])
        if any(root == candidate or root.startswith(candidate + "/") for candidate in app_roots):
            owner = "app"
        elif first_segments[0] in platform_first_segments or two in known_platform_roots:
            owner = "platform"
        else:
            owner = "third_party_candidate"
        histogram[root] = {"class_count": count, "owner": owner, "evidence_path": first_path.get(root)}
    return histogram