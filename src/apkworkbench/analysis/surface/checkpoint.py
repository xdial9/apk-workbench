"""Resumable artifact checkpoints for the surface overhaul (plan v2 P4).

Crash-safety contract: every checkpoint save is atomic (temp file + fsync +
os.replace + directory fsync); state is small JSON; a truncated/stale state
fails to parse and counts as "no checkpoint". callers decide resumption.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Self

STATE_SUFFIX = ".surface_checkpoint.json"
FACTS_NAME = "facts.jsonl"


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp.unlink(missing_ok=True)


class Checkpoint:
    """State machine persistence for one artifact's analysis run."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory).expanduser().resolve()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / STATE_SUFFIX

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("stage"), str):
            return None
        return data

    def save(self, stage: str, **fields: Any) -> None:
        payload = {"stage": stage, **fields}
        _atomic_write_bytes(
            self._path,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)


class FactWriter:
    """Append-only JSONL fact stream with cursor + resumable prefix semantics."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        self._handle: Any = None

    @property
    def path(self) -> Path:
        return self._path

    def __enter__(self) -> Self:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self._path, "a", encoding="utf-8")
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def write(self, fact: dict[str, Any]) -> None:
        if self._handle is None:
            raise RuntimeError("FactWriter used outside its context manager")
        self._handle.write(json.dumps(fact, sort_keys=True, separators=(",", ":")) + "\n")
        self._handle.flush()

    def sync(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            os.fsync(self._handle.fileno())

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    @staticmethod
    def read_facts(path: str | Path) -> Iterator[dict[str, Any]]:
        """Stream facts back; tolerate a truncated final line (crash tail)."""
        with Path(path).open("r", encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except ValueError:
                    continue  # truncated tail from a crash; resumable by design
                if isinstance(item, dict):
                    yield item
