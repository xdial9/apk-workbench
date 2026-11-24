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


def build_section_stripped_elf(
    *,
    bits: int = 64,
    little: bool = True,
    machine: int | None = None,
    symbols: tuple[dict, ...] = (),
    soname: str | None = None,
    needed: tuple[str, ...] = (),
    hash_style: str = "sysv",  # "sysv" | "gnu" | "none"
    vaddr_base: int = 0x10000,
) -> tuple[bytes, int]:
    """Build a section-stripped ELF (e_shoff=0) with PT_LOAD + PT_DYNAMIC.

    Returns ``(elf_bytes, dynsym_file_offset)`` so tests can assert exact
    ``file_offset`` citations on recovered symbols.
    """
    endian = "<" if little else ">"
    machine = machine if machine is not None else (183 if bits == 64 else 40)
    ehsize = 64 if bits == 64 else 52
    phentsize = 56 if bits == 64 else 32
    phnum = 2
    symentsize = 24 if bits == 64 else 16
    dynentsize = 16 if bits == 64 else 8

    # Order imports (shndx == 0) before exports (shndx != 0) so DT_GNU_HASH's
    # symoffset cleanly separates unhashed imports from hashed exports.
    imports = [item for item in symbols if item["shndx"] == 0]
    exports = [item for item in symbols if item["shndx"] != 0]
    ordered = imports + exports
    symoffset = 1 + len(imports)

    dynstr = bytearray(b"\x00")

    def add_str(text: str) -> int:
        offset = len(dynstr)
        dynstr.extend(text.encode("utf-8") + b"\x00")
        return offset

    sym_records = [(0, 0, 0, 0, 0, 0)]
    for item in ordered:
        sym_records.append((
            add_str(item["name"]), item["bind"], item["type"],
            item["value"], item["shndx"], item["size"],
        ))
    needed_offsets = [add_str(name) for name in needed]
    soname_offset = add_str(soname) if soname else 0

    dynsym = bytearray()
    for name_off, bind, sym_type, value, shndx, size in sym_records:
        info = (bind << 4) | sym_type
        if bits == 64:
            dynsym.extend(struct.pack(endian + "IBBHQQ", name_off, info, 0, shndx, value, size))
        else:
            dynsym.extend(struct.pack(endian + "IIIBBH", name_off, value, size, info, 0, shndx))

    hash_blob = bytearray()
    if hash_style == "sysv":
        nchain = len(sym_records)
        hash_blob.extend(struct.pack(endian + "II", 1, nchain))
        hash_blob.extend(struct.pack(endian + "I", 1 if nchain > 1 else 0))
        hash_blob.extend(struct.pack(endian + ("I" * nchain), *([0] * nchain)))
    elif hash_style == "gnu":
        nbuckets = 2
        bloom_size = 1
        bloom_shift = 5
        hash_blob.extend(struct.pack(endian + "IIII", nbuckets, symoffset, bloom_size, bloom_shift))
        hash_blob.extend(struct.pack(endian + ("Q" if bits == 64 else "I"), 0))
        if exports:
            # Put all exports in a single chain starting at bucket[1] = symoffset.
            hash_blob.extend(struct.pack(endian + "II", 0, symoffset))
            for idx in range(len(exports)):
                val = 0x12345670 | (1 if idx == len(exports) - 1 else 0)
                hash_blob.extend(struct.pack(endian + "I", val))
        else:
            hash_blob.extend(struct.pack(endian + "II", 0, 0))

    # Reserve space for header + 2 program headers, then place sections at 8-byte alignment.
    body = bytearray(ehsize + phnum * phentsize)

    def place(data: bytes) -> int:
        while len(body) % 8:
            body.append(0)
        off = len(body)
        body.extend(data)
        return off

    dynstr_off = place(bytes(dynstr))
    dynsym_off = place(bytes(dynsym))
    hash_off = place(bytes(hash_blob)) if hash_blob else 0

    dyn_entries: list[tuple[int, int]] = [
        (5, vaddr_base + dynstr_off),   # DT_STRTAB
        (10, len(dynstr)),              # DT_STRSZ
        (6, vaddr_base + dynsym_off),   # DT_SYMTAB
        (11, symentsize),               # DT_SYMENT
    ]
    if hash_style == "sysv":
        dyn_entries.append((4, vaddr_base + hash_off))         # DT_HASH
    elif hash_style == "gnu":
        dyn_entries.append((0x6FFFFEF5, vaddr_base + hash_off))  # DT_GNU_HASH
    for off in needed_offsets:
        dyn_entries.append((1, off))    # DT_NEEDED
    if soname:
        dyn_entries.append((14, soname_offset))  # DT_SONAME
    dyn_entries.append((0, 0))          # DT_NULL

    dyn_fmt = endian + ("qQ" if bits == 64 else "iI")
    dynamic = b"".join(struct.pack(dyn_fmt, tag, val) for tag, val in dyn_entries)
    dyn_off = place(dynamic)

    total_size = len(body)
    ph_fmt = endian + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
    if bits == 64:
        ph_load = struct.pack(ph_fmt, 1, 5, 0, vaddr_base, vaddr_base, total_size, total_size, 0x1000)
        ph_dyn = struct.pack(ph_fmt, 2, 6, dyn_off, vaddr_base + dyn_off, vaddr_base + dyn_off, len(dynamic), len(dynamic), 8)
    else:
        ph_load = struct.pack(ph_fmt, 1, 0, vaddr_base, vaddr_base, total_size, total_size, 5, 0x1000)
        ph_dyn = struct.pack(ph_fmt, 2, dyn_off, vaddr_base + dyn_off, vaddr_base + dyn_off, len(dynamic), len(dynamic), 6, 8)
    body[ehsize:ehsize + phentsize] = ph_load
    body[ehsize + phentsize:ehsize + 2 * phentsize] = ph_dyn

    ident = bytearray(b"\x7fELF")
    ident.append(2 if bits == 64 else 1)
    ident.append(1 if little else 2)
    ident.extend(b"\x01\x00\x00" + b"\x00" * 7)
    if bits == 64:
        header = struct.pack(
            endian + "HHIQQQIHHHHHH", 3, machine, 1, 0, ehsize, 0, 0,
            ehsize, phentsize, phnum, 0, 0, 0,
        )
    else:
        header = struct.pack(
            endian + "HHIIIIIHHHHHH", 3, machine, 1, 0, ehsize, 0, 0,
            ehsize, phentsize, phnum, 0, 0, 0,
        )
    body[0:16] = ident
    body[16:16 + len(header)] = header
    return bytes(body), dynsym_off


def test_section_stripped_elf_recovers_symbols_via_dt_hash_and_gnu_hash(tmp_path):
    syms = (
        symbol("Java_com_example_Foo_bar", bind=STB_GLOBAL, value=0x1100),
        symbol("_Z3foov", bind=STB_WEAK, value=0x1200),
        symbol("cfg_flag", bind=STB_GLOBAL, type_=STT_OBJECT, value=0x1300),
        symbol("malloc", bind=STB_GLOBAL, shndx=0, value=0),
    )
    for bits in (64, 32):
        for little in (True, False):
            for hash_style in ("sysv", "gnu"):
                blob, dynsym_off = build_section_stripped_elf(
                    bits=bits,
                    little=little,
                    symbols=syms,
                    soname="libstripped.so",
                    needed=("libc.so", "liblog.so"),
                    hash_style=hash_style,
                    vaddr_base=0x20000,
                )
                path = tmp_path / f"stripped_{bits}_{little}_{hash_style}.so"
                path.write_bytes(blob)

                result = parse_elf(path)

                assert result.ok
                assert result.sections == []
                assert any(w["code"] == "section_header_table_absent" for w in result.warnings)
                assert result.dynamic is not None
                assert result.dynamic.soname == "libstripped.so"
                assert result.dynamic.needed == ["libc.so", "liblog.so"]

                exports = {item.name: item for item in result.exports}
                imports = {item.name: item for item in result.imports}
                assert set(exports) == {"Java_com_example_Foo_bar", "_Z3foov", "cfg_flag"}
                assert set(imports) == {"malloc"}
                symentsize = 24 if bits == 64 else 16
                # Index 0 is null, index 1 is malloc (import ordered first), indices 2..4 are exports.
                assert imports["malloc"].file_offset == dynsym_off + 1 * symentsize
                assert exports["Java_com_example_Foo_bar"].file_offset == dynsym_off + 2 * symentsize
                assert exports["_Z3foov"].file_offset == dynsym_off + 3 * symentsize
                assert exports["cfg_flag"].file_offset == dynsym_off + 4 * symentsize


def test_section_stripped_elf_gnu_hash_imports_only_recovers_imports(tmp_path):
    blob, dynsym_off = build_section_stripped_elf(
        bits=64,
        little=True,
        symbols=(
            symbol("dlopen", bind=STB_GLOBAL, shndx=0, value=0),
            symbol("dlsym", bind=STB_GLOBAL, shndx=0, value=0),
        ),
        hash_style="gnu",
    )
    path = tmp_path / "imports_only.so"
    path.write_bytes(blob)

    result = parse_elf(path)

    assert result.ok
    assert result.exports == []
    assert [item.name for item in result.imports] == ["dlopen", "dlsym"]
    assert result.imports[0].file_offset == dynsym_off + 24
    assert result.imports[1].file_offset == dynsym_off + 48


def test_section_stripped_elf_bounds_and_missing_hash_warnings(tmp_path):
    # 1. Missing both DT_HASH and DT_GNU_HASH: honest warning, no fake symbols.
    no_hash, _ = build_section_stripped_elf(
        bits=64,
        symbols=(symbol("secret_fn"),),
        hash_style="none",
    )
    p1 = tmp_path / "nohash.so"
    p1.write_bytes(no_hash)
    res1 = parse_elf(p1)
    assert res1.ok
    assert res1.exports == []
    assert any(w["code"] == "dynamic_symbol_count_unavailable" for w in res1.warnings)

    # 2. Corrupt DT_HASH nchain exceeding MAX_SYMBOLS: rejected safely with warning.
    sysv_blob, _ = build_section_stripped_elf(
        bits=64, symbols=(symbol("a"),), hash_style="sysv", vaddr_base=0x10000,
    )
    p2 = tmp_path / "hugehash.so"
    p2.write_bytes(sysv_blob)
    base_res = parse_elf(p2)
    assert base_res.dynamic is not None and base_res.dynamic.hash_vaddr is not None
    huge_hash = bytearray(sysv_blob)
    hash_file_off = base_res.dynamic.hash_vaddr - 0x10000
    struct.pack_into("<I", huge_hash, hash_file_off + 4, 500_001)
    p2.write_bytes(bytes(huge_hash))

    res2 = parse_elf(p2)
    assert res2.ok
    assert res2.exports == []
    assert any(w["code"] == "symbol_count_invalid" for w in res2.warnings)
