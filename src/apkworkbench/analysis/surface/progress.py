"""Shared always-alive progress output for the surface overhaul (plan v2 P5).

Single-line, one writer, <=2s perceived-silence contract:
- refreshes in place with \\r on terminals,
- falls back to spaced newline lines on non-TTY writers (CI logs),
- a background heartbeat keeps the line alive while a single work unit takes
  long (with sub-unit hints supplied by the caller), so the terminal never
  looks frozen while work continues.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import TextIO

MIN_EMIT_INTERVAL = 0.5          # fastest we ever redraw
DEFAULT_HEARTBEAT = 2.0          # contract floor: never silent longer than this
CLOSE_LINES = 6.0                # non-TTY heartbeat spacing (beats) ~= 12s


class ProgressPrinter:
    """One-line progress display; thread-safe; never blocks the worker."""

    def __init__(
        self,
        *,
        title: str,
        writer: TextIO | None = None,
        heartbeat_interval: float = DEFAULT_HEARTBEAT,
        clock=time.monotonic,
    ):
        self._title = title
        self._writer = writer if writer is not None else sys.stdout
        self._heartbeat_interval = heartbeat_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._closed = False
        self._start = clock()
        self._last_emit = 0.0
        self._heartbeat_count = 0
        self._stage = ""
        self._counters: dict[str, str] = {}
        self._detail = ""
        self._is_tty = getattr(writer, "isatty", None)
        self._tty = bool(self._is_tty()) if callable(self._is_tty) else False
        self._thread = threading.Thread(
            target=self._heartbeat_loop, name="apkworkbench-progress", daemon=True
        )
        self._thread.start()

    # -- public API ------------------------------------------------------------
    def update(self, stage: str, detail: str = "", **counters: str) -> None:
        """Refresh the visible state (worker thread calls; cheap, throttled)."""
        with self._lock:
            if self._closed:
                return
            self._stage = str(stage)
            self._detail = str(detail)
            self._counters = dict(counters)
        self._emit(force=False)

    def close(self) -> None:
        """Stop the heartbeat and clear the progress line."""
        with self._lock:
            self._closed = True
        self._join_thread()
        with self._lock:
            if self._tty:
                self._write("\r" + " " * 200 + "\r")

    def line_text(self) -> str:
        with self._lock:
            return self._render()

    # -- internals --------------------------------------------------------------
    def _join_thread(self) -> None:
        thread = self._thread
        if thread.is_alive():
            thread.join(timeout=heartbeat_join_timeout(self._heartbeat_interval))

    def _heartbeat_loop(self) -> None:
        while True:
            with self._lock:
                if self._closed:
                    return
            time.sleep(self._heartbeat_interval)
            self._emit(force=True)

    def _emit(self, *, force: bool) -> None:
        now = self._clock()
        with self._lock:
            if self._closed:
                return
            due = now - self._last_emit >= MIN_EMIT_INTERVAL
            if not (force or due):
                return
            self._last_emit = now
            self._heartbeat_count += 1
            text = self._render(now)
        self._write("\r" + text if self._tty else text + "\n")

    def _render(self, now: float | None = None) -> str:
        if now is None:
            now = self._clock()
        elapsed = int(now - self._start)
        parts = [self._title]
        if self._stage:
            parts.append(self._stage)
        parts.extend(f"{key} {value}" for key, value in self._counters.items())
        if self._detail:
            parts.append(self._detail)
        parts.append(f"{elapsed}s")
        line = " ".join(part for part in parts if part)
        return line[: 400]

    def _write(self, text: str) -> None:
        try:
            self._writer.write(text)
            self._writer.flush()
        except (OSError, ValueError):
            # A closed terminal must never interrupt the working pipeline.
            pass


def heartbeat_join_timeout(interval: float) -> float:
    # Keep teardown snappy: at most one extra beat capped at 3s.
    return min(3.0, interval * 1.2)
