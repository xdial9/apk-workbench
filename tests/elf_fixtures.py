"""Synthetic ELF builders for native-parser tests.

Everything is built from bytes so the tests are hermetic: no host toolchain,
no committed binary blobs. Each builder writes a structurally valid ELF that
the parser must read back exactly.
"""
from __future__ import annotations

import struct
from pathlib import Path

SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NULL = 0

DT_NEEDED = 1
DT_SONAME = 14
DT_FLAGS = 30
DT_NULL = 0

STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_OBJECT, STT_FUNC = 1, 2


def symbol(name: str, *, bind: int = STB_GLOBAL, type_: int = STT_FUNC,
           value: int = 0x100, shndx: int = 1, size: int = 0x10) -> dict:
    return {
        "name": name, "bind": bind, "type": type_, "value": value,
        "shndx": shndx, "size": size,
    }


def _pad(blob: bytearray, alignment: int = 8) -> int:
    while len(blob) % alignment:
        blob.append(0)
    return len(blob)


def build_elf(
    *,
    bits: int = 64,
    little: bool = True,
    machine: int | None = None,
    symbols: tuple[dict, ...] = (),
    soname: str | None = None,
    needed: tuple[str, ...] = (),
    flags: int = 0,
    build_id: bytes | None = b"\xaa\xbb\xcc\xdd",
) -> bytes:
    endian = "<" if little else ">"
    machine = machine if machine is not None else (183 if bits == 64 else 40)
    ehsize = 64 if bits == 64 else 52
    shentsize = 64 if bits == 64 else 40
    symentsize = 24 if bits == 64 else 16
    dynentsize = 16 if bits == 64 else 8

    dynstr = bytearray(b"\x00")

    def add_str(text: str) -> int:
        offset = len(dynstr)
        dynstr.extend(text.encode("utf-8") + b"\x00")
        return offset

    sym_records = [(0, 0, 0, 0, 0, 0)]  # null symbol
    for item in symbols:
        sym_records.append((
            add_str(item["name"]), item["bind"], item["type"], item["value"],
            item["shndx"], item["size"],
        ))
    needed_offsets = [add_str(name) for name in needed]
    soname_offset = add_str(soname) if soname else 0

    dynsym = bytearray()
    for name_off, bind, type_, value, shndx, size in sym_records:
        info = (bind << 4) | type_
        if bits == 64:
            dynsym.extend(struct.pack(endian + "IBBHQQ", name_off, info, 0, shndx, value, size))
        else:
            dynsym.extend(struct.pack(endian + "IIIBBH", name_off, value, size, info, 0, shndx))

    dynamic = bytearray()
    dyn_fmt = endian + ("qQ" if bits == 64 else "iI")
    for offset in needed_offsets:
        dynamic.extend(struct.pack(dyn_fmt, DT_NEEDED, offset))
    if soname:
        dynamic.extend(struct.pack(dyn_fmt, DT_SONAME, soname_offset))
    if flags:
        dynamic.extend(struct.pack(dyn_fmt, DT_FLAGS, flags))
    dynamic.extend(struct.pack(dyn_fmt, DT_NULL, 0))

    note = bytearray()
    if build_id is not None:
        name = b"GNU\x00"
        note.extend(struct.pack(endian + "III", len(name), len(build_id), 3))
        note.extend(name)
        note.extend(b"\x00" * ((-len(note)) % 4))
        note.extend(build_id)
        note.extend(b"\x00" * ((-len(note)) % 4))

    shstrtab = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}

    def sec_name(text: str) -> int:
        if text not in name_offsets:
            name_offsets[text] = len(shstrtab)
            shstrtab.extend(text.encode("ascii") + b"\x00")
        return name_offsets[text]

    for text in (".dynstr", ".dynsym", ".dynamic", ".note.gnu.build-id", ".shstrtab"):
        sec_name(text)

    body = bytearray(ehsize)
    layout: list[dict] = []

    def place(name: str, type_: int, data: bytes, *, link: int = 0, info: int = 0,
              entsize: int = 0) -> None:
        _pad(body)
        offset = len(body)
        body.extend(data)
        layout.append({
            "name": sec_name(name), "type": type_, "offset": offset,
            "size": len(data), "link": link, "info": info, "entsize": entsize,
        })

    place(".dynstr", SHT_STRTAB, bytes(dynstr))
    place(".dynsym", SHT_DYNSYM, bytes(dynsym), link=1, info=1, entsize=symentsize)
    place(".dynamic", SHT_DYNAMIC, bytes(dynamic), link=1, info=0, entsize=dynentsize)
    if build_id is not None:
        place(".note.gnu.build-id", SHT_NOTE, bytes(note))
    place(".shstrtab", SHT_STRTAB, bytes(shstrtab))

    shoff = _pad(body)
    shnum = len(layout) + 1

    def shdr(entry: dict) -> bytes:
        if bits == 64:
            return struct.pack(
                endian + "IIQQQQIIQQ", entry["name"], entry["type"], 0, 0,
                entry["offset"], entry["size"], entry["link"], entry["info"],
                8, entry["entsize"],
            )
        return struct.pack(
            endian + "IIIIIIIIII", entry["name"], entry["type"], 0, 0,
            entry["offset"], entry["size"], entry["link"], entry["info"],
            4, entry["entsize"],
        )

    sh_table = bytearray(shdr({"name": 0, "type": SHT_NULL, "offset": 0, "size": 0,
                               "link": 0, "info": 0, "entsize": 0}))
    for entry in layout:
        sh_table.extend(shdr(entry))
    body.extend(sh_table)

    ident = bytearray(b"\x7fELF")
    ident.append(2 if bits == 64 else 1)
    ident.append(1 if little else 2)
    ident.append(1)          # EI_VERSION
    ident.append(0)          # EI_OSABI (System V)
    ident.append(0)          # EI_ABIVERSION
    ident.extend(b"\x00" * 7)

    if bits == 64:
        header = struct.pack(
            endian + "HHIQQQIHHHHHH", 3, machine, 1, 0, 0, shoff, 0,
            ehsize, 0, 0, shentsize, shnum, len(layout),  # shstrndx = .shstrtab index
        )
    else:
        header = struct.pack(
            endian + "HHIIIIIHHHHHH", 3, machine, 1, 0, 0, shoff, 0,
            ehsize, 0, 0, shentsize, shnum, len(layout),
        )
    body[0:16] = ident
    body[16:16 + len(header)] = header
    return bytes(body)


def write_elf(path: Path, **kwargs) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_elf(**kwargs))
    return path
