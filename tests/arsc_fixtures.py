"""Synthetic resources.arsc builder for the P2 resource tests.

Structurally correct ResTable: one package, a global string pool, per-type
string pools, typeSpec + type chunks. No aapt, no committed binary.
"""
from __future__ import annotations

import io
import struct
import zipfile

RES_TABLE = 0x0002
RES_STRING_POOL = 0x0001
RES_PACKAGE = 0x0200
RES_TYPE = 0x0201
RES_TYPE_SPEC = 0x0202

TYPE_STRING = 0x03
TYPE_REFERENCE = 0x01
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 0x100


def _len8(value: int) -> bytes:
    if value > 0x7F:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    return bytes([value])


def _len16(value: int) -> bytes:
    if value > 0x7FFF:
        return struct.pack("<HH", 0x8000 | (value >> 16), value & 0xFFFF)
    return struct.pack("<H", value)


def _chunk(chunk_type: int, header_extra: bytes, body: bytes) -> bytes:
    header_size = 8 + len(header_extra)
    return (
        struct.pack("<HHI", chunk_type, header_size, header_size + len(body))
        + header_extra
        + body
    )


def string_pool(strings: tuple[str, ...], *, utf8: bool = True) -> bytes:
    offsets: list[int] = []
    data = bytearray()
    for text in strings:
        offsets.append(len(data))
        if utf8:
            raw = text.encode("utf-8")
            utf16_length = len(text.encode("utf-16-le")) // 2
            data += _len8(utf16_length) + _len8(len(raw)) + raw + b"\x00"
        else:
            raw = text.encode("utf-16-le")
            data += _len16(len(raw) // 2) + raw + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    header_extra = struct.pack(
        "<IIIII",
        len(strings), 0, UTF8_FLAG if utf8 else 0, strings_start, 0,
    )
    offsets_blob = b"".join(struct.pack("<I", offset) for offset in offsets)
    return _chunk(RES_STRING_POOL, header_extra, offsets_blob + bytes(data))


def _type_spec(type_id: int, entry_count: int) -> bytes:
    header_extra = struct.pack("<BBHI", type_id, 0, 0, entry_count)
    body = b"".join(struct.pack("<I", 0) for _ in range(entry_count))
    return _chunk(RES_TYPE_SPEC, header_extra, body)


def _type_chunk(type_id: int, entries: list[tuple[int, int, int]]) -> bytes:
    config = struct.pack("<I", 64) + b"\x00" * 60
    entry_count = len(entries)
    header_size = 20 + len(config)
    entries_start = header_size + 4 * entry_count
    header_extra = (
        struct.pack("<BBHII", type_id, 0, 0, entry_count, entries_start) + config
    )
    offsets = b""
    body = b""
    for key_index, value_type, data in entries:
        offsets += struct.pack("<I", len(body))
        body += struct.pack("<HHI", 8, 0, key_index)
        body += struct.pack("<HBBI", 8, 0, value_type, data)
    return _chunk(RES_TYPE, header_extra, offsets + body)


def _package(
    package_id: int,
    package_name: str,
    type_pool: bytes,
    key_pool: bytes,
    chunks: bytes,
    type_count: int,
) -> bytes:
    name_bytes = package_name.encode("utf-16-le")[:254].ljust(256, b"\x00")
    header_extra = (
        struct.pack("<I", package_id)
        + name_bytes
        + struct.pack(
            "<IIII",
            288,              # typeStrings (offset from package start)
            type_count,       # lastPublicType
            288 + len(type_pool),  # keyStrings
            0,                # lastPublicKey
        )
        + struct.pack("<I", 0)  # typeIdOffset
    )
    return _chunk(RES_PACKAGE, header_extra, type_pool + key_pool + chunks)


def build_arsc(
    *,
    package_name: str = "com.example.app",
    package_id: int = 0x7F,
    global_strings: tuple[str, ...] = ("Hello", "World"),
    types: tuple[tuple[str, tuple[tuple[str, int, int], ...]], ...] = (
        ("string", (("app_name", TYPE_STRING, 0), ("greeting", TYPE_STRING, 1))),
        ("bool", (("flag", TYPE_INT_BOOLEAN, 1),)),
        ("integer", (("count", TYPE_INT_DEC, 42),)),
        ("string", (("alias", TYPE_REFERENCE, 0x7F010000),)),
    ),
) -> bytes:
    """Build a resources.arsc. Duplicate type names are merged into one chunk."""
    merged: dict[str, list[tuple[str, int, int]]] = {}
    for type_name, entries in types:
        merged.setdefault(type_name, []).extend(entries)
    type_names = tuple(merged)
    key_names: list[str] = []
    for entries in merged.values():
        for key, _value_type, _data in entries:
            key_names.append(key)

    type_pool = string_pool(type_names, utf8=False)
    key_pool = string_pool(tuple(key_names), utf8=True)
    chunks = b""
    for type_id, (type_name, entries) in enumerate(merged.items(), start=1):
        chunks += _type_spec(type_id, len(entries))
        chunks += _type_chunk(
            type_id,
            [(key_names.index(key), value_type, data) for key, value_type, data in entries],
        )
    package = _package(
        package_id, package_name, type_pool, key_pool, chunks, len(type_names)
    )
    global_pool = string_pool(global_strings, utf8=True)
    return _chunk(RES_TABLE, struct.pack("<I", 1), global_pool + package)


def apk_with_arsc(arsc: bytes, entries: dict[str, bytes] | None = None) -> bytes:
    payload = dict(entries or {"AndroidManifest.xml": b"<manifest/>"})
    payload["resources.arsc"] = arsc
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in payload.items():
            archive.writestr(name, data)
    return buffer.getvalue()
