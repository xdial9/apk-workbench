"""N1-N3: pure-stdlib ELF reader (header, sections, dynamic, symbols)."""
from __future__ import annotations

import struct

from apkworkbench.analysis.surface.native_elf import parse_elf
from tests.elf_fixtures import (
    STB_GLOBAL,
    STB_WEAK,
    STT_OBJECT,
    build_elf,
    symbol,
    write_elf,
)


def test_parse_elf64_little_endian_header_and_sections(tmp_path):
    path = write_elf(tmp_path / "lib.so", bits=64, little=True, machine=183)

    result = parse_elf(path)

    assert result.ok
    header = result.header
    assert header.class_type == "ELF64"
    assert header.data_encoding == "little"
    assert header.machine == "EM_AARCH64"
    assert header.type_name == "ET_DYN"
    names = [section.name for section in result.sections]
    assert names[:4] == ["", ".dynstr", ".dynsym", ".dynamic"]
    assert ".shstrtab" in names


def test_parse_elf32_little_endian_header(tmp_path):
    path = write_elf(tmp_path / "lib32.so", bits=32, little=True, machine=40)

    result = parse_elf(path)

    assert result.ok
    assert result.header.class_type == "ELF32"
    assert result.header.machine == "EM_ARM"
    assert result.header.entry == 0


def test_parse_elf64_big_endian_header(tmp_path):
    path = write_elf(tmp_path / "libbe.so", bits=64, little=False, machine=8)

    result = parse_elf(path)

    assert result.ok
    assert result.header.data_encoding == "big"
    assert result.header.machine == "EM_MIPS"
    assert [section.name for section in result.sections][:2] == ["", ".dynstr"]


def test_truncated_file_returns_reason_not_exception(tmp_path):
    path = tmp_path / "short.so"
    path.write_bytes(b"\x7fELF\x02\x01")

    result = parse_elf(path)

    assert not result.ok
    assert result.reason == "file_truncated"


def test_garbage_file_is_not_elf(tmp_path):
    path = tmp_path / "garbage.so"
    path.write_bytes(b"PK\x03\x04 this is a zip, not an elf" * 4)

    result = parse_elf(path)

    assert not result.ok
    assert result.reason == "not_elf_file"


def test_unsupported_class_and_encoding_are_reported(tmp_path):
    bad_class = bytearray(build_elf(bits=64))
    bad_class[4] = 9
    path = tmp_path / "badclass.so"
    path.write_bytes(bytes(bad_class))

    assert parse_elf(path).reason == "unsupported_class"

    bad_data = bytearray(build_elf(bits=64))
    bad_data[5] = 9
    path2 = tmp_path / "baddata.so"
    path2.write_bytes(bytes(bad_data))

    assert parse_elf(path2).reason == "unsupported_data_encoding"


def test_dynamic_entries_soname_needed_flags_build_id(tmp_path):
    path = write_elf(
        tmp_path / "libdyn.so",
        soname="libfoo.so",
        needed=("libc.so", "liblog.so"),
        flags=0x8,
        build_id=b"\x01\x02\x03\x04\x05\x06",
    )

    result = parse_elf(path)

    assert result.ok
    assert result.dynamic is not None
    assert result.dynamic.soname == "libfoo.so"
    assert result.dynamic.needed == ["libc.so", "liblog.so"]
    assert result.dynamic.flags == 0x8
    assert result.build_id == "010203040506"


def test_symbols_split_into_exports_and_imports(tmp_path):
    path = write_elf(
        tmp_path / "libsym.so",
        symbols=(
            symbol("Java_com_example_Foo_bar", bind=STB_GLOBAL, value=0x1000),
            symbol("_Z3foov", bind=STB_WEAK, value=0x2000),
            symbol("my_global", bind=STB_GLOBAL, type_=STT_OBJECT, value=0x3000),
            symbol("malloc", bind=STB_GLOBAL, shndx=0, value=0),
            symbol("local_helper", bind=0, value=0x4000),
        ),
    )

    result = parse_elf(path)

    exports = {item.name: item for item in result.exports}
    imports = {item.name: item for item in result.imports}
    assert set(exports) == {"Java_com_example_Foo_bar", "_Z3foov", "my_global"}
    assert imports.keys() == {"malloc"}
    assert exports["Java_com_example_Foo_bar"].value == 0x1000
    assert exports["my_global"].type_name == "OBJECT"
    assert exports["_Z3foov"].bind_name == "WEAK"
    # A local symbol is neither export nor import.
    assert "local_helper" not in exports and "local_helper" not in imports


def test_symbol_table_with_bad_string_offset_is_safe(tmp_path):
    path = tmp_path / "libbad.so"
    blob = bytearray(build_elf(symbols=(symbol("good_symbol"),)))
    # Rewrite the first real symbol's st_name to a huge offset (past .dynstr).
    path.write_bytes(bytes(blob))
    result = parse_elf(path)
    assert result.ok  # sanity: unmodified file parses
    dynsym = result.section(".dynsym")
    assert dynsym is not None
    entry = bytearray(
        blob[dynsym.offset + dynsym.entsize:dynsym.offset + 2 * dynsym.entsize]
    )
    struct.pack_into("<I", entry, 0, 0x7FFFFFFF)
    blob[dynsym.offset + dynsym.entsize:dynsym.offset + 2 * dynsym.entsize] = entry
    path.write_bytes(bytes(blob))

    broken = parse_elf(path)

    assert broken.ok
    # The symbol keeps a defined body but its name is unresolvable, so it is
    # neither exported under a fake name nor silently ignored: it is counted.
    assert broken.exports == []
    assert any(
        item["code"] == "symbol_name_unresolved" for item in broken.warnings
    )


def test_section_header_table_absent_is_a_warning_not_a_failure(tmp_path):
    blob = bytearray(build_elf(bits=64))
    struct.pack_into("<Q", blob, 40, 0)  # e_shoff = 0
    path = tmp_path / "nosections.so"
    path.write_bytes(bytes(blob))

    result = parse_elf(path)

    assert result.ok
    assert result.sections == []
    assert any(item["code"] == "section_header_table_absent" for item in result.warnings)


def test_parse_does_not_read_whole_file(monkeypatch, tmp_path):
    """A 4 MB library must never be slurped: every read stays bounded."""
    path = write_elf(tmp_path / "big.so", symbols=(symbol("a"),))
    with path.open("ab") as handle:
        handle.write(b"\x00" * (4 * 1024 * 1024))
    reads: list[int] = []
    original = bytes.__len__

    from apkworkbench.analysis.surface import native_elf

    class SpyReader(native_elf._Reader):
        def read(self, offset: int, length: int):
            reads.append(length)
            return super().read(offset, length)

    monkeypatch.setattr(native_elf, "_Reader", SpyReader)
    result = parse_elf(path)

    assert result.ok
    assert reads and max(reads) < 4 * 1024 * 1024
    assert original is bytes.__len__
