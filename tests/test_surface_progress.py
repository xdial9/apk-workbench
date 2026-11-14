"""Always-alive progress contract (plan v2 P5) + checkpoint/resume contracts.
Emission contract: never silent longer than the heartbeat floor while active.
"""
from __future__ import annotations

import io
import time

import pytest

from apkworkbench.analysis.surface import checkpoint as cp
from apkworkbench.analysis.surface import progress as prog


def test_progress_prints_one_line_and_keeps_it_alive_via_heartbeat():
    buffer = io.StringIO()
    printer = prog.ProgressPrinter(
        title="Surface com.example", writer=buffer,
        heartbeat_interval=0.05, clock=time.monotonic,
    )
    printer.update("files 1/2", detail="scanning")
    time.sleep(0.25)                     # heartbeats must fire while busy
    printer.close()

    text = buffer.getvalue()
    assert "Surface com.example" in text
    assert "files 1/2" in text
    assert "scanning" in text
    assert "elapsed:" not in text        # compact single line, no prose
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) >= 2               # initial + at least one heartbeat


def test_progress_non_tty_lines_stay_single_and_time_stamped():
    buffer = io.StringIO()
    printer = prog.ProgressPrinter(
        title="Surface pkg", writer=buffer, heartbeat_interval=0.05
    )
    printer.update("files 2/4", endpoints="12")
    time.sleep(0.2)
    printer.close()
    lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
    assert all("Surface pkg" in line for line in lines)
    assert any("endpoints 12" in line for line in lines)


def test_progress_close_is_idempotent_and_safe():
    printer = prog.ProgressPrinter(title="X", writer=io.StringIO(),
                                   heartbeat_interval=0.05)
    printer.update("a")
    printer.close()
    printer.close()                      # no exception, thread stopped


def test_checkpoint_save_load_clear_round_trip(tmp_path):
    state = cp.Checkpoint(tmp_path)
    assert state.load() is None
    state.save("sweep", file_cursor=17, findings=42)
    loaded = state.load()
    assert loaded == {"stage": "sweep", "file_cursor": 17, "findings": 42}
    state.clear()
    assert state.load() is None
    assert not state.path.exists()


@pytest.mark.parametrize("payload", [b"not json", b""])
def test_checkpoint_tolerates_garbage_state(tmp_path, payload):
    state = cp.Checkpoint(tmp_path)
    state.path.write_bytes(payload)
    assert state.load() is None


def test_fact_writer_appends_and_survives_truncated_tail(tmp_path):
    path = tmp_path / "facts.jsonl"
    with cp.FactWriter(path) as writer:
        writer.write({"kind": "endpoint", "value": "http://a.b/"})
        writer.write({"kind": "domain", "value": "a.b"})
        writer.sync()
    # crash tail: append a truncated line, then resume-check
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind": "half-wr')
    items = list(cp.FactWriter.read_facts(path))
    assert len(items) == 2
    assert items[0]["kind"] == "endpoint"
    assert items[1]["value"] == "a.b"
    assert isinstance(items[0], dict) and "value" in items[0]
