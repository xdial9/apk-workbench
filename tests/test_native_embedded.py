"""N13: native code inside containers (packed .so, plugin APKs in assets)."""
from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from apkworkbench.analysis.apk_surface import analyze_apk_surface
from apkworkbench.analysis.surface import native
from tests.elf_fixtures import build_elf, symbol, write_elf
from tests.test_native_analysis import MANIFEST, make_tree

PLUGIN_SMALI = (
    ".class public Lcom/example/Plugin;\n"
    ".method public native run()V\n.end method\n"
    ".method public static load()V\n"
    '    const-string v0, "plugin"\n'
    "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
    "    return-void\n"
    ".end method\n"
)


def write_zip(path: Path, members: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def test_library_inside_plugin_apk_is_parsed_mapped_and_cited(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Plugin.smali").write_text(PLUGIN_SMALI, encoding="utf-8")
    write_zip(
        root / "assets/plugins.apk",
        {
            "lib/arm64-v8a/libplugin.so": build_elf(
                symbols=(symbol("Java_com_example_Plugin_run", value=0x400),),
            ),
            "assets/noise.txt": b"just text",
        },
    )

    result = analyze_apk_surface(root)

    citation = "assets/plugins.apk!lib/arm64-v8a/libplugin.so"
    inventory = {item["path"]: item for item in result["inventory"]["native_analysis"]}
    assert citation in inventory
    assert inventory[citation]["state"] == "parsed"
    assert inventory[citation]["exports_total"] == 1
    assert result["inventory"]["native_embedded_libraries"] == [citation]
    assert result["metrics"]["native_embedded_libraries_found"] == 1
    assert result["metrics"]["native_embedded_libraries_parsed"] == 1
    assert result["metrics"]["native_embedded_containers_scanned"] == 1
    assert result["coverage"]["native_embedded_libraries"] == "success"

    # The JNI join works across the container boundary.
    entry = next(fact for fact in result["facts"] if fact["kind"] == "native_jni_entry")
    assert entry["value"] == f"{citation}::Java_com_example_Plugin_run"
    assert entry["java_method"] == "run"
    symbol_cite = next(item for item in entry["evidence"] if "offset" in item)
    assert symbol_cite["path"] == citation
    assert isinstance(symbol_cite["offset"], int)

    # A System.loadLibrary("plugin") resolves to the embedded library.
    load = next(fact for fact in result["facts"] if fact["kind"] == "native_library_load")
    assert load["value"] == citation


def test_packed_so_container_is_unpacked_and_parsed(tmp_path):
    root = make_tree(tmp_path)
    packed = write_zip(
        root / "lib/arm64-v8a/libjiagu.so",
        {"lib/arm64-v8a/libhidden.so": build_elf(symbols=(symbol("hidden_export"),))},
    )
    assert packed.is_file()

    result = analyze_apk_surface(root)

    states = {item["path"]: item["state"] for item in result["inventory"]["native_analysis"]}
    assert states["lib/arm64-v8a/libjiagu.so"] == "not_elf"
    assert states["lib/arm64-v8a/libjiagu.so!lib/arm64-v8a/libhidden.so"] == "parsed"
    exports = [
        fact["value"] for fact in result["facts"] if fact["kind"] == "native_export"
    ]
    assert exports == [
        "lib/arm64-v8a/libjiagu.so!lib/arm64-v8a/libhidden.so::hidden_export"
    ]
    # The outer file is still named by observation, not just failed.
    payload = next(fact for fact in result["facts"] if fact["kind"] == "native_payload_not_elf")
    assert payload["observed_content_kind"] == "zip"


def test_corrupt_container_is_a_diagnostic_not_a_crash(tmp_path):
    root = make_tree(tmp_path)
    (root / "assets").mkdir(parents=True, exist_ok=True)
    (root / "assets/broken.apk").write_bytes(b"PK\x03\x04" + b"\x00" * 32)

    result = analyze_apk_surface(root)

    assert any(
        item["code"] == "native_container_unreadable" for item in result["diagnostics"]
    )
    assert result["coverage"]["native_embedded_libraries"] == "partial"
    assert result["status"] == "partial"


def test_container_member_limit_is_counted(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "MAX_MEMBERS_PER_CONTAINER", 1)
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/many.apk",
        {
            "lib/arm64-v8a/libone.so": build_elf(symbols=(symbol("one"),)),
            "lib/arm64-v8a/libtwo.so": build_elf(symbols=(symbol("two"),)),
        },
    )

    result = analyze_apk_surface(root)

    assert any(
        item["code"] == "native_container_member_limit" for item in result["diagnostics"]
    )
    assert result["metrics"]["native_embedded_libraries_found"] == 1
    assert result["metrics"]["native_embedded_members_found"] == 2
    assert result["coverage"]["native_embedded_libraries"] == "partial"


def test_embedded_member_that_is_not_elf_is_named(tmp_path):
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/payload.apk",
        {"lib/arm64-v8a/libbogus.so": b"\xde\xad\xbe\xef" * 8},
    )

    result = analyze_apk_surface(root)

    payload = next(
        fact for fact in result["facts"]
        if fact["kind"] == "native_payload_not_elf"
        and "!" in fact["value"]
    )
    assert payload["reason"] == "not_elf_payload"
    assert payload["observed_content_kind"] == "unknown"
    assert payload["evidence"] == [
        {"path": "assets/payload.apk!lib/arm64-v8a/libbogus.so", "offset": 0}
    ]


def test_extracted_members_are_deleted_after_analysis(monkeypatch, tmp_path):
    root = make_tree(tmp_path)
    write_zip(
        root / "assets/plugins.apk",
        {"lib/arm64-v8a/libplugin.so": build_elf(symbols=(symbol("x"),))},
    )
    created: list[str] = []
    real_mkstemp = tempfile.mkstemp

    def spy(*args, **kwargs):
        fd, name = real_mkstemp(*args, **kwargs)
        created.append(name)
        return fd, name

    monkeypatch.setattr(native.tempfile, "mkstemp", spy)

    analyze_apk_surface(root)

    assert created
    assert all(not Path(name).exists() for name in created)


def test_loose_library_still_works_alongside_embedded(tmp_path):
    root = make_tree(tmp_path)
    write_elf(root / "lib/arm64-v8a/libloose.so", symbols=(symbol("loose"),))
    write_zip(
        root / "assets/plugins.apk",
        {"lib/arm64-v8a/libplugin.so": build_elf(symbols=(symbol("plug"),))},
    )

    result = analyze_apk_surface(root)

    values = {fact["value"] for fact in result["facts"] if fact["kind"] == "native_export"}
    assert values == {
        "lib/arm64-v8a/libloose.so::loose",
        "assets/plugins.apk!lib/arm64-v8a/libplugin.so::plug",
    }
    assert result["metrics"]["native_files_found"] == 2  # 1 loose + 1 embedded
    assert MANIFEST  # shared fixture constant remains importable
