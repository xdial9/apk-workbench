"""N12: adversarial native inputs. Nothing crashes, nothing is silent."""
from __future__ import annotations

import struct
import time

from apkworkbench.analysis.apk_surface import analyze_apk_surface
from apkworkbench.analysis.surface.native_elf import parse_elf
from tests.elf_fixtures import build_elf, symbol, write_elf
from tests.test_native_analysis import MANIFEST, make_tree

MAX_PARSE_SECONDS = 2.0


def test_zip_named_so_is_skipped_with_a_reason(tmp_path):
    root = make_tree(tmp_path)
    (root / "lib/arm64-v8a/libpacked.so").write_bytes(b"PK\x03\x04" + b"\x00" * 64)

    result = analyze_apk_surface(root)

    inventory = result["inventory"]["native_analysis"]
    assert [item["state"] for item in inventory] == ["not_elf"]
    assert inventory[0]["reason"] == "not_elf_file"
    assert result["metrics"]["native_files_skipped"] == 1
    assert result["status"] == "partial"
    assert any(item["code"] == "native_not_elf" for item in result["diagnostics"])


def test_section_table_pointing_past_eof_warns_and_never_raises(tmp_path):
    blob = bytearray(build_elf(symbols=(symbol("foo"),)))
    struct.pack_into("<Q", blob, 40, 0x7FFF_FFF0)  # e_shoff far past EOF
    path = tmp_path / "badsoffset.so"
    path.write_bytes(bytes(blob))

    result = parse_elf(path)

    assert result.ok  # header is valid; the section table is not readable
    assert result.sections == []
    assert any(
        item["code"] in {"section_header_table_truncated", "section_header_table_corrupt"}
        for item in result.warnings
    )


def test_absurd_section_count_is_refused_not_allocated(tmp_path):
    blob = bytearray(build_elf(symbols=(symbol("foo"),)))
    struct.pack_into("<H", blob, 60, 0xFFFF)  # e_shnum -> extended numbering
    path = tmp_path / "manySections.so"
    path.write_bytes(bytes(blob))

    result = parse_elf(path)

    assert result.ok
    assert any(item["code"].startswith("section_header_count") for item in result.warnings)


def test_zero_export_library_is_complete_not_broken(tmp_path):
    root = make_tree(tmp_path)
    write_elf(root / "lib/arm64-v8a/libempty.so")

    result = analyze_apk_surface(root)

    assert result["metrics"]["native_exports_total"] == 0
    assert result["metrics"]["native_jni_exports_total"] == 0
    assert result["metrics"]["native_jni_mapping_complete"] is True
    assert result["coverage"]["native_jni_mapping"] == "not_applicable"
    assert not [item for item in result["findings"] if item["rule_id"].startswith("native_")]


def test_native_declaration_without_library_export_is_not_invented(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Main.smali").write_text(
        ".class public Lcom/example/Main;\n"
        ".method public native missing()V\n.end method\n",
        encoding="utf-8",
    )
    write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("unrelated"),))

    result = analyze_apk_surface(root)

    assert result["inventory"]["jni_entries"] == []
    assert result["metrics"]["native_jni_exports_total"] == 0
    assert result["metrics"]["native_jni_mapping_complete"] is True


def test_sparse_200mb_library_parses_from_header_only(tmp_path):
    path = tmp_path / "sparse.so"
    path.write_bytes(build_elf(symbols=(symbol("foo"),)))
    with path.open("r+b") as handle:
        handle.truncate(200 * 1024 * 1024)  # sparse: header stays valid

    started = time.monotonic()
    result = parse_elf(path)
    elapsed = time.monotonic() - started

    assert result.ok
    assert elapsed < MAX_PARSE_SECONDS  # header/sections only, never the payload
    assert [item.name for item in result.exports] == ["foo"]


def test_hostile_string_input_does_not_raise(tmp_path):
    """NUL runs, invalid UTF-16, and 8-bit noise in one file."""
    root = make_tree(tmp_path)
    path = write_elf(root / "lib/arm64-v8a/libnoise.so", symbols=(symbol("foo"),))
    noise = (
        b"\x00" * 4096
        + b"\xff\xfe\xfd\x00\x00\x80\x00"
        + "héllo-short".encode("utf-16-le")
        + b"\x00" * 17
        + b"password=hunter2"
        + b"\x00" * 1024
    )
    with path.open("ab") as handle:
        handle.write(noise)

    result = analyze_apk_surface(root)

    assert result["status"] in {"success", "partial"}
    hints = [item for item in result["facts"] if item["kind"] == "native_secret_hint"]
    assert any("password=hunter2" in item["value"] for item in hints)
    assert all(isinstance(item["evidence"][0]["offset"], int) for item in hints)


def test_no_manifest_still_reports_native_state(tmp_path):
    root = tmp_path / "apktool"
    (root / "lib/arm64-v8a").mkdir(parents=True)
    write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("foo"),))

    result = analyze_apk_surface(root)

    assert result["metrics"]["native_files_found"] == 1
    assert result["metrics"]["native_files_parsed"] == 1
    assert result["coverage"]["native_libraries"] == "analyzed"
    assert (root / "AndroidManifest.xml").exists() is False
    assert MANIFEST  # fixture constant is intentionally available to other tests
