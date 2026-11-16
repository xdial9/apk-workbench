"""Per-file coverage ledger (P0) — every entry accounted, checked != skipped.

Completeness law (AGENTS.md): a skipped file must appear in the coverage
ledger as skipped, with a reason, and "checked" and "skipped" must be
different states. Until this module the analyzer exported only COUNTS
(``inventory.classification``), so the handoff could not prove what it had
looked at, and a file that was never opened was indistinguishable from one
that was read and found empty.

One JSONL record per tree entry, plus symlinks and unreadable entries. The
record shape is closed and stable: the same keys in every run, ``null`` when a
field does not apply. No hash here — hashing every file is the freeze step
(Unit 1), not the scan step; this ledger adds no I/O beyond the ``stat`` the
classifier already performed.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from apkworkbench.analysis.surface.classify import (
    ARCHIVE_KINDS,
    TEXT_SUFFIXES,
    DecodedTree,
)

FILES_FILENAME = "files.jsonl"

# Closed status set. A value outside this set is a bug, not a new state.
SCANNED_TEXT = "scanned_text"
ANALYSED_NATIVE = "analysed_native"
SKIPPED_CONTAINER = "skipped_container"
SKIPPED_BINARY = "skipped_binary"
SKIPPED_UNSUPPORTED = "skipped_unsupported"
SKIPPED_SYMLINK = "skipped_symlink"
UNDECODABLE = "undecodable"

STATUSES = (
    SCANNED_TEXT,
    ANALYSED_NATIVE,
    SKIPPED_CONTAINER,
    SKIPPED_BINARY,
    SKIPPED_UNSUPPORTED,
    SKIPPED_SYMLINK,
    UNDECODABLE,
)

# Closed reason set, paired with the status that may carry it.
REASONS = {
    "container_not_extracted": SKIPPED_CONTAINER,
    "elf_without_library_suffix": SKIPPED_BINARY,
    "binary_content": SKIPPED_BINARY,
    "no_text_suffix": SKIPPED_UNSUPPORTED,
    "empty_file": SKIPPED_UNSUPPORTED,
    "text_read_failed": UNDECODABLE,
    "unreadable_entry": UNDECODABLE,
    "symlink_never_followed": SKIPPED_SYMLINK,
}

LIBRARY_SUFFIXES = frozenset({".so", ".a"})

_CHECKED = frozenset({SCANNED_TEXT, ANALYSED_NATIVE})


def _record(
    path: str,
    status: str,
    *,
    reason: str | None = None,
    size_bytes: int = 0,
    suffix: str = "",
    content_kind: str | None = None,
    analysed_by: str | None = None,
) -> dict[str, Any]:
    return {
        "path": path,
        "status": status,
        "reason": reason,
        "size_bytes": size_bytes,
        "suffix": suffix,
        "content_kind": content_kind,
        "analysed_by": analysed_by,
    }


def build_file_ledger(
    tree: DecodedTree,
    *,
    scanned: set[str],
    read_failures: dict[str, str] | None = None,
    library_suffixes: frozenset[str] = LIBRARY_SUFFIXES,
) -> list[dict[str, Any]]:
    """One record per tree entry, sorted by path.

    ``scanned`` holds the relative paths the text sweep actually read;
    ``read_failures`` holds the ones it tried and could not. A text candidate
    that is in neither is reported as undecodable rather than assumed read.
    """
    failures = read_failures or {}
    records: list[dict[str, Any]] = []
    for entry in tree.entries:
        relative = entry.relative
        base = {
            "size_bytes": entry.size_bytes,
            "suffix": entry.suffix,
            "content_kind": entry.content_kind,
        }
        if relative in scanned:
            records.append(_record(
                relative, SCANNED_TEXT, analysed_by="text_sweep", **base,
            ))
            continue
        if relative in failures:
            records.append(_record(
                relative, UNDECODABLE, reason="text_read_failed", **base,
            ))
            continue
        if entry.suffix in library_suffixes:
            records.append(_record(
                relative, ANALYSED_NATIVE, analysed_by="native_elf", **base,
            ))
            continue
        if entry.content_kind == "unreadable":
            records.append(_record(
                relative, UNDECODABLE, reason="unreadable_entry", **base,
            ))
            continue
        if entry.suffix in TEXT_SUFFIXES:
            # Text-routed by the sweep, yet never opened: a read failure, not a
            # skip. Anything else would report an unchecked file as checked.
            records.append(_record(
                relative, UNDECODABLE, reason="text_read_failed", **base,
            ))
            continue
        if entry.content_kind == "empty":
            records.append(_record(
                relative, SKIPPED_UNSUPPORTED, reason="empty_file", **base,
            ))
            continue
        if entry.content_kind in ARCHIVE_KINDS:
            records.append(_record(
                relative, SKIPPED_CONTAINER, reason="container_not_extracted", **base,
            ))
            continue
        if entry.content_kind == "elf":
            # A real ELF that is not named .so/.a never reaches the native pass.
            records.append(_record(
                relative, SKIPPED_BINARY, reason="elf_without_library_suffix", **base,
            ))
            continue
        if entry.content_kind is None:
            records.append(_record(
                relative, SKIPPED_UNSUPPORTED, reason="no_text_suffix", **base,
            ))
            continue
        records.append(_record(
            relative, SKIPPED_BINARY, reason="binary_content", **base,
        ))

    for relative in tree.symlinks:
        records.append(_record(
            relative, SKIPPED_SYMLINK, reason="symlink_never_followed",
        ))
    for relative in tree.unreadable:
        records.append(_record(
            relative, UNDECODABLE, reason="unreadable_entry",
        ))

    records.sort(key=lambda item: item["path"])
    return records


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts + the vocabulary, so the AI can read the ledger without parsing it."""
    by_status: dict[str, int] = {status: 0 for status in STATUSES}
    by_reason: dict[str, int] = {reason: 0 for reason in REASONS}
    for record in records:
        by_status[record["status"]] = by_status.get(record["status"], 0) + 1
        reason = record.get("reason")
        if reason:
            by_reason[reason] = by_reason.get(reason, 0) + 1
    checked = sum(by_status[status] for status in _CHECKED)
    return {
        "files_jsonl": FILES_FILENAME,
        "total": len(records),
        "checked": checked,
        "not_checked": len(records) - checked,
        "by_status": dict(sorted(by_status.items())),
        "by_reason": {key: value for key, value in sorted(by_reason.items()) if value},
        "status_vocabulary": list(STATUSES),
        "reason_vocabulary": dict(sorted(REASONS.items())),
    }


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


def write_file_ledger(
    directory: str | Path, records: list[dict[str, Any]]
) -> Path:
    """Write ``files.jsonl`` into ``directory`` atomically, one record per line."""
    path = Path(directory) / FILES_FILENAME
    stream = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )
    _atomic_write_bytes(path, stream.encode("utf-8"))
    return path
