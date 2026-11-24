"""Crash-consistency tests for sweep checkpoints (N1 fix)."""
from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface.checkpoint import Checkpoint
from apkworkbench.analysis.surface.sweep import SweepState


_B64_URL_A = base64.b64encode(b"https://decoded-a.example.com/v1/a").decode("ascii")
_B64_URL_B = base64.b64encode(b"https://decoded-b.example.com/v1/b").decode("ascii")

_SMALI_TEMPLATE = (
    '.class public Lcom/example/F{idx};\n'
    '.super Ljava/lang/Object;\n'
    'const-string v0, "https://api{idx}.example.test/v1/{idx}"\n'
    'const-string v1, "http://cleartext{idx}.example.org/path"\n'
    '.method public static run()V\n'
    '    return-void\n'
    '.end method\n'
)


def _build_synthetic_tree(root: Path, count: int, *, include_same_line_dups: bool = False) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest package="com.example.consistency" android:versionCode="1"><application/></manifest>',
        encoding="utf-8",
    )
    smali_dir = root / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True, exist_ok=True)
    for idx in range(count):
        content = _SMALI_TEMPLATE.format(idx=idx)
        if include_same_line_dups and idx == 0:
            # Two distinct encoded URLs on the same line emit two findings with
            # identical (rule_id, path, line); neither may be dropped on restore.
            content += f'const-string v2, "{_B64_URL_A} {_B64_URL_B}"\n'
        (smali_dir / f"F{idx:05d}.smali").write_text(content, encoding="utf-8")
    return root


def test_crash_between_sweep_state_and_checkpoint_save_preserves_exact_counts(
    tmp_path: Path, monkeypatch
) -> None:
    tree = _build_synthetic_tree(tmp_path / "apktool", 10, include_same_line_dups=True)

    clean = apk_surface.analyze_apk_surface(tree, output_dir=tmp_path / "clean_out")

    ckpt_dir = tmp_path / "ckpt"
    resume_out = tmp_path / "resume_out"
    monkeypatch.setattr(apk_surface, "CHECKPOINT_EVERY_FILES", 3)

    real_save = Checkpoint.save
    save_calls = 0

    def crash_on_second_save(self, stage: str, **fields):
        nonlocal save_calls
        save_calls += 1
        if save_calls == 2:
            raise RuntimeError("simulated SIGKILL between sweep_state.json and checkpoint.save")
        return real_save(self, stage, **fields)

    monkeypatch.setattr(Checkpoint, "save", crash_on_second_save)

    try:
        apk_surface.analyze_apk_surface(
            tree,
            output_dir=resume_out,
            checkpoint_dir=ckpt_dir,
        )
    except RuntimeError as exc:
        assert "simulated SIGKILL" in str(exc)
    else:
        raise AssertionError("Expected simulated crash during second Checkpoint.save")

    # Verify the N1 window was hit: sweep_state.json is ahead of .surface_checkpoint.json.
    state_data = json.loads((ckpt_dir / "sweep_state.json").read_text(encoding="utf-8"))
    ckpt_data = Checkpoint(ckpt_dir).load()
    assert ckpt_data is not None
    assert len(state_data["processed_files"]) == 6
    assert len(ckpt_data["processed_files"]) == 3

    # Resume with Checkpoint.save restored; already-checkpointed files must be skipped.
    monkeypatch.setattr(Checkpoint, "save", real_save)
    swept_on_resume: list[str] = []
    real_sweep_text = SweepState.sweep_text

    def tracking_sweep(self, **kwargs):
        swept_on_resume.append(kwargs["relative"])
        return real_sweep_text(self, **kwargs)

    monkeypatch.setattr(SweepState, "sweep_text", tracking_sweep)

    resumed = apk_surface.analyze_apk_surface(
        tree,
        output_dir=resume_out,
        checkpoint_dir=ckpt_dir,
    )

    assert set(swept_on_resume).isdisjoint(set(state_data["processed_files"]))
    assert len(swept_on_resume) == 5  # 11 total text files (manifest + 10 smali) - 6 already in state
    assert resumed["metrics"]["finding_count"] == clean["metrics"]["finding_count"]
    assert resumed["metrics"]["distinct_finding_count"] == clean["metrics"]["distinct_finding_count"]
    assert len(resumed["facts"]) == len(clean["facts"])
    assert resumed["metrics"]["fact_count"] == clean["metrics"]["fact_count"]
    assert resumed["findings"] == clean["findings"]
    assert resumed["facts"] == clean["facts"]


def test_crash_on_first_checkpoint_before_checkpoint_file_exists(
    tmp_path: Path, monkeypatch
) -> None:
    tree = _build_synthetic_tree(tmp_path / "apktool", 8, include_same_line_dups=True)
    clean = apk_surface.analyze_apk_surface(tree, output_dir=tmp_path / "clean_out")

    ckpt_dir = tmp_path / "ckpt"
    resume_out = tmp_path / "resume_out"
    monkeypatch.setattr(apk_surface, "CHECKPOINT_EVERY_FILES", 4)

    real_save = Checkpoint.save

    def crash_on_first_save(self, stage: str, **fields):
        raise RuntimeError("simulated SIGKILL before first checkpoint.save")

    monkeypatch.setattr(Checkpoint, "save", crash_on_first_save)

    try:
        apk_surface.analyze_apk_surface(
            tree,
            output_dir=resume_out,
            checkpoint_dir=ckpt_dir,
        )
    except RuntimeError as exc:
        assert "simulated SIGKILL" in str(exc)
    else:
        raise AssertionError("Expected simulated crash during first Checkpoint.save")

    state_data = json.loads((ckpt_dir / "sweep_state.json").read_text(encoding="utf-8"))
    assert len(state_data["processed_files"]) == 4
    assert Checkpoint(ckpt_dir).load() is None

    monkeypatch.setattr(Checkpoint, "save", real_save)
    swept_on_resume: list[str] = []
    real_sweep_text = SweepState.sweep_text

    def tracking_sweep(self, **kwargs):
        swept_on_resume.append(kwargs["relative"])
        return real_sweep_text(self, **kwargs)

    monkeypatch.setattr(SweepState, "sweep_text", tracking_sweep)

    resumed = apk_surface.analyze_apk_surface(
        tree,
        output_dir=resume_out,
        checkpoint_dir=ckpt_dir,
    )

    assert set(swept_on_resume).isdisjoint(set(state_data["processed_files"]))
    assert len(swept_on_resume) == 5  # 9 total text files - 4 already in state
    assert Checkpoint(ckpt_dir).load() is not None
    assert resumed["metrics"]["finding_count"] == clean["metrics"]["finding_count"]
    assert resumed["metrics"]["distinct_finding_count"] == clean["metrics"]["distinct_finding_count"]
    assert len(resumed["facts"]) == len(clean["facts"])
    assert resumed["findings"] == clean["findings"]


def test_subprocess_sigkill_mid_sweep_and_resume_matches_clean_run(tmp_path: Path) -> None:
    file_count = 4500
    tree = _build_synthetic_tree(tmp_path / "apktool", file_count)

    clean = apk_surface.analyze_apk_surface(tree, output_dir=tmp_path / "clean_out")

    ckpt_dir = tmp_path / "ckpt"
    resume_out = tmp_path / "resume_out"
    child_code = (
        "from pathlib import Path\n"
        "from apkworkbench.analysis.apk_surface import analyze_apk_surface\n"
        f"analyze_apk_surface(Path({str(tree)!r}), output_dir=Path({str(resume_out)!r}), "
        f"checkpoint_dir=Path({str(ckpt_dir)!r}))\n"
    )
    env = dict(os.environ)
    src_root = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    proc = subprocess.Popen(
        [sys.executable, "-c", child_code],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    state_path = ckpt_dir / "sweep_state.json"
    deadline = time.monotonic() + 30.0
    try:
        while time.monotonic() < deadline:
            if state_path.is_file() and state_path.stat().st_size > 0:
                break
            if proc.poll() is not None:
                break
            time.sleep(0.01)
        assert state_path.is_file(), (
            f"Child exited early ({proc.poll()}) without writing sweep_state.json: "
            f"{proc.stderr.read().decode('utf-8', errors='replace') if proc.stderr else ''}"
        )
        assert proc.poll() is None, "Child finished sweep before SIGKILL could be delivered"
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)

    assert proc.returncode == -signal.SIGKILL
    saved_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert 0 < len(saved_state["processed_files"]) < file_count + 1

    resumed = apk_surface.analyze_apk_surface(
        tree,
        output_dir=resume_out,
        checkpoint_dir=ckpt_dir,
    )

    assert resumed["metrics"]["finding_count"] == clean["metrics"]["finding_count"]
    assert resumed["metrics"]["distinct_finding_count"] == clean["metrics"]["distinct_finding_count"]
    assert len(resumed["facts"]) == len(clean["facts"])
    assert resumed["metrics"]["fact_count"] == clean["metrics"]["fact_count"]
    assert resumed["inventory"]["text_files_scanned"] == clean["inventory"]["text_files_scanned"]
    assert resumed["findings"] == clean["findings"]
