"""Overflow shards (P0c) — a cap must count and move data, never delete it.

Completeness law (AGENTS.md): "Overflow means counted + sharded + coverage =
partial. Never replace overflow with []." A cap that silently stops emitting
turns "too much data" into "no data", which is the one failure mode the
doctrine forbids outright.

The analyzer keeps the first N records in ``static-analysis.json`` so the
primary plane stays readable, and streams everything past the cap into
``shards/<prefix>-part-NNN.jsonl``. ``shards-index.json`` describes each part
(file, record count, first/last key, sha256) plus exact totals, so the AI can
read the index and open only the part it needs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

SHARDS_DIRNAME = "shards"
INDEX_FILENAME = "shards-index.json"
DEFAULT_PART_RECORDS = 5_000
KEY_PREVIEW_CHARS = 500


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class ShardWriter:
    """Append-only JSONL shards with a deterministic index.

    Parts are created lazily: an artifact that never overflows leaves no
    ``shards/`` directory and no index behind.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        prefix: str = "overflow",
        part_records: int = DEFAULT_PART_RECORDS,
    ) -> None:
        self._root = Path(directory)
        self._prefix = prefix
        self._part_records = max(1, int(part_records))
        self._parts: list[dict[str, Any]] = []
        self._by_kind: dict[str, int] = {}
        self._handle: Any = None
        self._digest: Any = None
        self._path: Path | None = None
        self._part_no = 0
        self._part_count = 0
        self._first_key: str | None = None
        self._last_key: str | None = None
        self._total = 0

    # -- internals ---------------------------------------------------------
    def _open_part(self) -> None:
        self._close_part()
        self._part_no += 1
        directory = self._root / SHARDS_DIRNAME
        directory.mkdir(parents=True, exist_ok=True)
        name = f"{self._prefix}-part-{self._part_no:03d}.jsonl"
        path = directory / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self._handle = os.fdopen(fd, "w", encoding="utf-8")
        self._digest = hashlib.sha256()
        self._path = path
        self._part_count = 0
        self._first_key = None
        self._last_key = None

    def _close_part(self) -> None:
        if self._handle is None:
            return
        self._handle.close()
        self._handle = None
        assert self._path is not None and self._digest is not None
        self._parts.append({
            "file": f"{SHARDS_DIRNAME}/{self._path.name}",
            "records": self._part_count,
            "first_key": self._first_key,
            "last_key": self._last_key,
            "sha256": self._digest.hexdigest(),
        })

    # -- public API --------------------------------------------------------
    def write(self, kind: str, key: Any, record: dict[str, Any]) -> None:
        if self._handle is None or self._part_count >= self._part_records:
            self._open_part()
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        self._handle.write(line)
        self._digest.update(line.encode("utf-8"))
        preview = str(key)[:KEY_PREVIEW_CHARS]
        if self._first_key is None:
            self._first_key = preview
        self._last_key = preview
        self._part_count += 1
        self._total += 1
        self._by_kind[kind] = self._by_kind.get(kind, 0) + 1

    @property
    def total(self) -> int:
        return self._total

    def count(self, kind: str) -> int:
        return self._by_kind.get(kind, 0)

    def close(self) -> dict[str, Any] | None:
        """Flush the open part and write the index. None when nothing overflowed."""
        self._close_part()
        if not self._parts:
            return None
        index = {
            "schema_version": 1,
            "parts_dir": SHARDS_DIRNAME,
            "key_preview_chars": KEY_PREVIEW_CHARS,
            "parts": self._parts,
            "totals": {
                "records": self._total,
                "by_kind": dict(sorted(self._by_kind.items())),
            },
        }
        _atomic_write_json(self._root / INDEX_FILENAME, index)
        return index
