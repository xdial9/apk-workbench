from __future__ import annotations

import time
from pathlib import Path

import pytest

from apkworkbench.analysis import androguard_dex


def test_androguard_worker_result_is_returned_from_isolated_process(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"fixture")
    payload = {
        "status": "success",
        "metrics": {"dex_files": 2, "external_methods_referenced": 7},
        "coverage": {"dex_parsing": "success"},
        "external_method_references": [{"full_name": "Lokhttp3/Call; execute ()"}],
    }
    monkeypatch.setattr(androguard_dex, "_analyze_in_worker", lambda _path: payload)

    result = androguard_dex.analyze_apk_dex(apk, timeout_seconds=5)

    assert result == payload


def test_androguard_analysis_timeout_terminates_worker(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"fixture")

    def slow_worker(_path):
        time.sleep(5)
        return {"status": "success"}

    monkeypatch.setattr(androguard_dex, "_analyze_in_worker", slow_worker)

    result = androguard_dex.analyze_apk_dex(apk, timeout_seconds=1)

    assert result["status"] == "timed_out"
    assert result["coverage"]["dex_parsing"] == "timed_out"


def test_androguard_rejects_missing_symlink_and_non_apk_paths(tmp_path):
    missing = tmp_path / "missing.apk"
    text_file = tmp_path / "notes.txt"
    text_file.write_text("not an APK", encoding="utf-8")
    outside = tmp_path / "outside.apk"
    outside.write_bytes(b"fixture")
    symlink = tmp_path / "linked.apk"
    symlink.symlink_to(outside)

    with pytest.raises(ValueError, match="regular APK file"):
        androguard_dex.analyze_apk_dex(missing)
    with pytest.raises(ValueError, match="regular APK file"):
        androguard_dex.analyze_apk_dex(text_file)
    with pytest.raises(ValueError, match="regular APK file"):
        androguard_dex.analyze_apk_dex(symlink)
