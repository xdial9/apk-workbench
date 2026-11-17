"""P6: code inside containers (.dex/.jar/.apk nested in zip/APK/JAR).

Mirrors tests/test_native_embedded.py style: a zip containing a .dex must
have its classes appear in dex_analysis with container! citation; nested
containers resolve up to MAX_CONTAINER_DEPTH with a diagnostic on limit hit;
oversized members produce a diagnostic and partial coverage without OOM.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from apkworkbench.analysis.apk_surface import analyze_apk_surface
from apkworkbench.analysis.surface import native
from tests.test_native_analysis import make_tree

# Extract a real classes.dex from the dexfixture APK for use as a fixture member.
_DEXFIXTURE = Path(__file__).parent / "fixtures" / "dexfixture" / "dexfixture.apk"


def _read_dex_fixture() -> bytes:
    with zipfile.ZipFile(_DEXFIXTURE) as archive:
        return archive.read("classes.dex")


DEX_BYTES = _read_dex_fixture()


def write_zip(path: Path, members: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def _dex_classes(result: dict) -> dict[str, dict]:
    """Index class_model entries by class_name for assertions."""
    return {
        entry["class_name"]: entry
        for entry in result.get("dex_analysis", {}).get("class_model", [])
    }


def test_zip_containing_dex_classes_cited_with_container_prefix(tmp_path):
    """A .dex inside a zip: its classes appear with container! citation."""
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/plugin.zip",
        {"classes.dex": DEX_BYTES},
    )

    result = analyze_apk_surface(root)

    classes = _dex_classes(result)
    # The dexfixture APK has at least one class; check they carry dex_source.
    assert classes, "expected classes from embedded DEX in class_model"
    for entry in result["dex_analysis"]["class_model"]:
        if entry.get("dex_source"):
            assert entry["dex_source"] == "assets/plugin.zip!classes.dex", entry
    # At least one entry should have the container citation.
    cited = [
        e for e in result["dex_analysis"]["class_model"]
        if e.get("dex_source") == "assets/plugin.zip!classes.dex"
    ]
    assert cited, "no class_model entry cited the embedded container"
    assert result["coverage"]["dex_semantic_analysis"] == "success"
    assert any(
        d["code"] == "code_container_unreadable"
        for d in result.get("diagnostics", [])
    ) is False


def test_container_nested_inside_container_resolves_to_depth_limit(tmp_path):
    """zip-in-zip: the inner .dex is cited with the full container chain."""
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/outer.zip",
        {
            "inner.jar": write_zip(
                tmp_path / "inner.jar",
                {"classes2.dex": DEX_BYTES},
            ).read_bytes(),
        },
    )

    result = analyze_apk_surface(root)

    classes = result["dex_analysis"].get("class_model", [])
    cited = [
        e for e in classes
        if e.get("dex_source") == "assets/outer.zip!inner.jar!classes2.dex"
    ]
    assert cited, (
        "no class_model entry cited the nested container chain; "
        f"got {[e.get('dex_source') for e in classes]}"
    )
    assert result["coverage"]["dex_semantic_analysis"] == "success"


def test_depth_limit_produces_diagnostic_not_silent_stop(monkeypatch, tmp_path):
    """MAX_CONTAINER_DEPTH hit: diagnostic emitted, nested contents not scanned."""
    monkeypatch.setattr(native, "MAX_CONTAINER_DEPTH", 1)
    root = make_tree(tmp_path)
    # outer.zip contains inner.jar which contains classes3.dex.
    # With max_depth=1, outer.zip!inner.jar is at depth 1; its contents
    # (classes3.dex) would be at depth 2 > max_depth=1 -> diagnostic.
    write_zip(
        root / "assets/outer.zip",
        {
            "inner.jar": write_zip(
                tmp_path / "inner.jar",
                {"classes3.dex": DEX_BYTES},
            ).read_bytes(),
        },
    )

    result = analyze_apk_surface(root)

    assert any(
        d["code"] == "code_container_depth_limit" for d in result.get("diagnostics", [])
    ), f"expected code_container_depth_limit diagnostic; got {result.get('diagnostics', [])}"
    # The inner classes should NOT be cited because depth limit stopped recursion.
    cited_inner = [
        e for e in result.get("dex_analysis", {}).get("class_model", [])
        if e.get("dex_source") == "assets/outer.zip!inner.jar!classes3.dex"
    ]
    assert not cited_inner, "depth limit should have prevented scanning nested contents"
    assert result["coverage"]["dex_semantic_analysis"] in {"success", "partial"}


def test_oversized_embedded_member_diagnostic_and_partial(monkeypatch, tmp_path):
    """Member exceeding MAX_EMBEDDED_LIBRARY_BYTES: diagnostic, partial coverage, no OOM."""
    monkeypatch.setattr(native, "MAX_EMBEDDED_LIBRARY_BYTES", 100)
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/big.zip",
        {"classes.dex": b"\x00" * 1000},
    )

    result = analyze_apk_surface(root)

    assert any(
        d["code"] == "code_embedded_byte_limit" for d in result.get("diagnostics", [])
    ), f"expected code_embedded_byte_limit diagnostic; got {result.get('diagnostics', [])}"
    assert result["coverage"]["dex_semantic_analysis"] in {"success", "partial"}
    # Nothing OOMs — the run completes.
    assert result["status"] in {"success", "partial"}


def test_embedded_code_temp_files_deleted_after_analysis(tmp_path):
    """Extracted temp files are cleaned up after analysis."""
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/plugin.zip",
        {"classes.dex": DEX_BYTES},
    )

    created: list[str] = []
    real_mkstemp = __import__("tempfile").mkstemp

    def spy(*args, **kwargs):
        fd, name = real_mkstemp(*args, **kwargs)
        created.append(name)
        return fd, name

    monkeypatch_target = __import__("apkworkbench.analysis.surface.native", fromlist=["tempfile"])
    original = monkeypatch_target.tempfile.mkstemp
    monkeypatch_target.tempfile.mkstemp = spy
    try:
        analyze_apk_surface(root)
    finally:
        monkeypatch_target.tempfile.mkstemp = original

    assert created, "no temp files were created"
    assert all(not Path(name).exists() for name in created), "temp files not deleted"
