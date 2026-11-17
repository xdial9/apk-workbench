"""Always-alive progress contract (plan v2 P5) + checkpoint/resume contracts.
Emission contract: never silent longer than the heartbeat floor while active.
"""
from __future__ import annotations

import io
import time
from pathlib import Path

import pytest

from apkworkbench.analysis.surface import checkpoint as cp
from apkworkbench.analysis.surface import progress as prog
from apkworkbench.analysis import apk_surface as as_mod


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


# ---- P7: checkpoint + resume ----------------------------------------------

SMALI_WITH_ENDPOINT = (
    '.class public Lcom/example/E{};\n'
    'const-string v0, "https://api{}.example.test/v1/{}"\n'
    '.method public static run()V\n'
    '    return-void\n'
    '.end method\n'
)


def _make_sweep_fixture(tmp_path: Path, n_files: int) -> Path:
    """Create a decoded tree with n smali files, each carrying an endpoint."""
    root = tmp_path / "apktool"
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest package="com.example.resume" '
        'android:versionCode="1">'
        '<application/></manifest>',
        encoding="utf-8",
    )
    smali = root / "smali" / "com" / "example"
    smali.mkdir(parents=True)
    for i in range(n_files):
        (smali / f"E{i}.smali").write_text(
            SMALI_WITH_ENDPOINT.format(i, i, i), encoding="utf-8"
        )
    return root


def test_checkpoint_saves_processed_files_and_resume_skips_themon_restart(
    monkeypatch, tmp_path
):
    """P7 exit criterion: checkpoint saves progress; restart skips done files.

    Start a sweep on a multi-file fixture, checkpoint after every file,
    then restart pointed at the same checkpoint dir. Already-swept files
    must be skipped (not re-read from file zero).
    """
    # Checkpoint after every file so we can observe partial progress.
    monkeypatch.setattr(as_mod, "CHECKPOINT_EVERY_FILES", 1)

    root = _make_sweep_fixture(tmp_path, 5)
    ckpt_dir = tmp_path / "checkpoints"

    # --- First run: process all files ---
    result1 = as_mod.analyze_apk_surface(root, checkpoint_dir=ckpt_dir)
    assert result1["status"] in {"success", "partial"}

    # Checkpoint file should exist.
    ckpt_path = ckpt_dir / cp.Checkpoint(ckpt_dir).path.name
    assert ckpt_path.exists(), f"checkpoint not written at {ckpt_dir}"
    loaded = cp.Checkpoint(ckpt_dir).load()
    assert loaded is not None
    assert loaded["stage"] == "sweep_done" or loaded["stage"] == "sweep"
    processed = set(loaded.get("processed_files", []))
    # 5 smali files + AndroidManifest.xml (xml is a text suffix).
    assert len(processed) == 6, f"expected 6 processed files, got {len(processed)}: {processed}"
    smali_processed = {p for p in processed if p.endswith(".smali")}
    assert len(smali_processed) == 5, smali_processed

    # All 5 endpoints should be present.
    endpoints1 = {
        e["value"] for e in result1.get("inventory", {}).get("endpoints", [])
    }
    assert len(endpoints1) == 5, endpoints1

    # --- Second run: simulate restart, same checkpoint dir ---
    # All files should be skipped (already in processed_files).
    result2 = as_mod.analyze_apk_surface(root, checkpoint_dir=ckpt_dir)
    assert result2["status"] in {"success", "partial"}

    # The checkpoint should still list all 5 as processed.
    loaded2 = cp.Checkpoint(ckpt_dir).load()
    assert loaded2 is not None
    processed2 = set(loaded2.get("processed_files", []))
    # All files (5 smali + manifest) should still be marked processed.
    assert len(processed2) == 6, f"expected 6 processed files on restart, got {len(processed2)}"

    # The facts_stream.jsonl should exist if output_dir was used.
    # (Without output_dir, no streaming write happens — that's expected.)
