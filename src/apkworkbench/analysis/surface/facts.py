"""Fingerprint fact store (plan v2 S5) — dedup law implementation.

Fact = (kind, normalized value, fingerprint, evidence, count). Identical
fingerprints merge; representative evidence is capped (≤3) while counts
stay exact. This is the shape the AI handoff consumes (plan §8B: dense,
deduped, pointerized).
"""
from __future__ import annotations

import hashlib
from typing import Any

REPRESENTATIVE_EVIDENCE_CAP = 3


def fingerprint(value: Any) -> str:
    normalized = str(value).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class FactStore:
    def __init__(self, *, evidence_cap: int = REPRESENTATIVE_EVIDENCE_CAP):
        self._by_key: dict[tuple[str, str], dict[str, Any]] = {}
        self._evidence_cap = evidence_cap

    def add(
        self,
        kind: str,
        value: Any,
        evidence: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
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
        """Sorted, capped-evidence export (machine plane; summary shape)."""
        exported: list[dict[str, Any]] = []
        for record in self.records():
            entry = dict(record)
            entry["evidence"] = record["evidence"][: self._evidence_cap]
            entry["evidence_truncated"] = (
                len(record["evidence"]) > self._evidence_cap
            )
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
        histogram[root] = {"class_count": count, "owner": owner}
    return histogram