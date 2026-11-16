"""Resource table reader (P2a) — resources.arsc -> id / type / name / value.

Until this module a resource id was an opaque hex constant. `const v0, 0x7f0b0012`
in smali told the analyst nothing; the decoded `res/values/*.xml` gives names
but not the ids the bytecode actually uses.

This reads the binary `resources.arsc` from the original APK (the decoded tree
usually does not contain it) and streams one record per (id, config):

    {"id": "0x7f0b0012", "package": "com.example.app", "type": "string",
     "name": "app_name", "config": "default", "value": "Foo",
     "value_type": "string", "reference": null}

Laws obeyed:
  * every record is cited by its id and package, never by position;
  * an unknown chunk or entry shape is counted and named, never skipped
    silently;
  * the file is read once, bounded by the APK size; records are streamed to a
    sink so the table never has to exist twice in memory.
"""
from __future__ import annotations

import re
import struct
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

RES_TABLE_TYPE = 0x0002
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203

FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02
FLAG_COMPACT = 0x0008

TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

VALUE_TYPE_NAMES = {
    TYPE_REFERENCE: "reference",
    TYPE_ATTRIBUTE: "attribute",
    TYPE_STRING: "string",
    TYPE_FLOAT: "float",
    TYPE_DIMENSION: "dimension",
    TYPE_FRACTION: "fraction",
    TYPE_DYNAMIC_REFERENCE: "dynamic_reference",
    TYPE_DYNAMIC_ATTRIBUTE: "dynamic_attribute",
    TYPE_INT_DEC: "int_dec",
    TYPE_INT_HEX: "int_hex",
    TYPE_INT_BOOLEAN: "boolean",
}

DIMENSION_UNITS = ("px", "dp", "sp", "pt", "in", "mm")
FRACTION_UNITS = ("%", "%p")

NO_ENTRY = 0xFFFFFFFF

# `res/values*/*.xml` element tag -> ARSC type name (only where they differ).
VALUE_TAG_ALIASES = {"string-array": "array", "integer-array": "array"}
VALUE_ENTRY_RE = re.compile(r'<([a-zA-Z][a-zA-Z0-9_-]*)\b[^>]*?\bname="([^"]+)"')
VALUE_TYPE_ATTR_RE = re.compile(r'\btype="([^"]+)"')


class ResourceTableError(ValueError):
    """Raised when the table structure is unreadable."""


def index_value_files(root: Path, files: list[Path]) -> dict[tuple[str, str], str]:
    """Map (type, name) -> decoded `res/values*/...xml` that declares it.

    ARSC carries no file attribution, so the definition file is recovered from
    the decoded tree. Plain `res/values/` wins over a qualified config dir, and
    the first file in sorted order wins within a class.
    """
    plain: dict[tuple[str, str], str] = {}
    other: dict[tuple[str, str], str] = {}
    for path in files:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if not relative.startswith("res/values") or not relative.endswith(".xml"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        target = plain if relative.startswith("res/values/") else other
        for match in VALUE_ENTRY_RE.finditer(text):
            tag = match.group(1)
            name = match.group(2)
            if tag == "item":
                type_match = VALUE_TYPE_ATTR_RE.search(match.group(0))
                if type_match is None:
                    continue
                tag = type_match.group(1)
            tag = VALUE_TAG_ALIASES.get(tag, tag)
            target.setdefault((tag, name), relative)
    merged = dict(other)
    merged.update(plain)
    return merged


def _u8(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 1 > len(buf):
        raise ResourceTableError("read past end")
    return buf[offset]


def _u16(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(buf):
        raise ResourceTableError("read past end")
    return struct.unpack_from("<H", buf, offset)[0]


def _u32(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(buf):
        raise ResourceTableError("read past end")
    return struct.unpack_from("<I", buf, offset)[0]


def _chunk_header(buf: bytes, offset: int) -> tuple[int, int, int]:
    """(type, header_size, size) for the chunk at ``offset``."""
    chunk_type = _u16(buf, offset)
    header_size = _u16(buf, offset + 2)
    size = _u32(buf, offset + 4)
    if header_size < 8 or size < header_size or offset + size > len(buf):
        raise ResourceTableError(
            f"chunk at {offset} has header_size={header_size} size={size}"
        )
    return chunk_type, header_size, size


def _length8(buf: bytes, offset: int) -> tuple[int, int]:
    first = _u8(buf, offset)
    if first & 0x80:
        return ((first & 0x7F) << 8) | _u8(buf, offset + 1), offset + 2
    return first, offset + 1


def _length16(buf: bytes, offset: int) -> tuple[int, int]:
    first = _u16(buf, offset)
    if first & 0x8000:
        return ((first & 0x7FFF) << 16) | _u16(buf, offset + 2), offset + 4
    return first, offset + 2


def parse_string_pool(buf: bytes, start: int) -> list[str]:
    """Decode a ResStringPool chunk (UTF-8 or UTF-16) into plain strings."""
    chunk_type, header_size, size = _chunk_header(buf, start)
    if chunk_type != RES_STRING_POOL_TYPE:
        raise ResourceTableError(f"expected string pool at {start}, got {chunk_type:#x}")
    count = _u32(buf, start + 8)
    flags = _u32(buf, start + 16)
    strings_start = _u32(buf, start + 20)
    utf8 = bool(flags & 0x100)
    if count > 2_000_000:
        raise ResourceTableError(f"string pool count {count} is implausible")
    base = start + strings_start
    strings: list[str] = []
    for index in range(count):
        offset = _u32(buf, start + header_size + index * 4)
        cursor = base + offset
        if utf8:
            _utf16_length, cursor = _length8(buf, cursor)
            length, cursor = _length8(buf, cursor)
            end = cursor + length
            if end > start + size:
                raise ResourceTableError("utf-8 string overruns the pool")
            strings.append(buf[cursor:end].decode("utf-8", errors="replace"))
        else:
            length, cursor = _length16(buf, cursor)
            end = cursor + length * 2
            if end > start + size:
                raise ResourceTableError("utf-16 string overruns the pool")
            strings.append(buf[cursor:end].decode("utf-16-le", errors="replace"))
    return strings


def _config_string(buf: bytes, start: int, size: int) -> str:
    """Compact, deterministic config label (language-region-dpi-sdk)."""
    if size < 28:
        return "default"
    language = buf[start + 8:start + 10]
    region = buf[start + 10:start + 12]
    density = _u16(buf, start + 14)
    sdk = _u16(buf, start + 24) if size >= 26 else 0
    parts: list[str] = []
    if language != b"\x00\x00":
        try:
            parts.append(language.decode("ascii"))
        except UnicodeDecodeError:
            parts.append("??")
    if region != b"\x00\x00":
        try:
            parts.append(region.decode("ascii"))
        except UnicodeDecodeError:
            parts.append("??")
    if density:
        parts.append(f"dpi{density}")
    if sdk:
        parts.append(f"v{sdk}")
    return "-".join(parts) if parts else "default"


def _decode_value(
    value_type: int, data: int, global_strings: list[str]
) -> tuple[Any, str]:
    name = VALUE_TYPE_NAMES.get(value_type, f"type_{value_type:#04x}")
    if value_type == TYPE_STRING:
        if 0 <= data < len(global_strings):
            return global_strings[data], name
        return f"<string index {data} out of range>", name
    if value_type in (TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE):
        return f"@{data:#010x}", name
    if value_type in (TYPE_ATTRIBUTE, TYPE_DYNAMIC_ATTRIBUTE):
        return f"?{data:#010x}", name
    if value_type == TYPE_INT_BOOLEAN:
        return ("true" if data else "false"), name
    if value_type == TYPE_INT_HEX:
        return f"{data:#010x}", name
    if value_type == TYPE_INT_DEC:
        signed = struct.unpack("<i", struct.pack("<I", data))[0]
        return str(signed), name
    if value_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data))[0]), name
    if value_type in (TYPE_DIMENSION, TYPE_FRACTION):
        units = DIMENSION_UNITS if value_type == TYPE_DIMENSION else FRACTION_UNITS
        unit = data & 0xF
        magnitude = struct.unpack("<f", struct.pack("<I", data & 0xFFFFFF00))[0]
        suffix = units[unit] if unit < len(units) else f"unit{unit}"
        return f"{magnitude:g}{suffix}", name
    return f"{data:#010x}", name


def _remember(
    index: dict[int, dict[str, Any]],
    record: dict[str, Any],
    package_id: int,
    type_id: int,
    entry_index: int,
) -> None:
    """Keep one record per id, preferring the default config."""
    numeric = (package_id << 24) | (type_id << 16) | entry_index
    existing = index.get(numeric)
    if existing is None or (
        existing.get("config") != "default" and record.get("config") == "default"
    ):
        index[numeric] = record


def _package_entries(
    buf: bytes,
    start: int,
    size: int,
    sink: Callable[[dict[str, Any]], None] | None,
    diagnostics: list[dict[str, str]],
    type_counts: dict[str, int],
    package_names: dict[int, str],
    global_strings: list[str],
    value_files: dict[tuple[str, str], str] | None = None,
    id_index: dict[int, dict[str, Any]] | None = None,
) -> int:
    """Walk one package chunk; return the number of value records emitted."""
    header_size = _u16(buf, start + 2)
    package_id = _u32(buf, start + 8)
    name_end = start + 12 + 256
    raw_name = buf[start + 12:name_end]
    package_name = raw_name.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    type_strings_offset = _u32(buf, start + 268)
    key_strings_offset = _u32(buf, start + 276)
    package_names[package_id] = package_name
    type_strings = parse_string_pool(buf, start + type_strings_offset)
    key_strings = parse_string_pool(buf, start + key_strings_offset)

    emitted = 0
    cursor = start + header_size
    end = start + size
    while cursor + 8 <= end:
        chunk_type, chunk_header_size, chunk_size = _chunk_header(buf, cursor)
        if chunk_type == RES_TABLE_TYPE_TYPE:
            emitted += _type_entries(
                buf, cursor, chunk_header_size, chunk_size, package_id,
                package_name, type_strings, key_strings, global_strings,
                sink, diagnostics, type_counts, value_files, id_index,
            )
        elif chunk_type not in (
            RES_TABLE_TYPE_SPEC_TYPE, RES_TABLE_LIBRARY_TYPE, RES_STRING_POOL_TYPE,
        ):
            diagnostics.append({
                "code": "resource_chunk_unknown",
                "message": f"package {package_name}: chunk type {chunk_type:#06x} skipped",
            })
        cursor += chunk_size
    return emitted


def _type_entries(
    buf: bytes,
    start: int,
    header_size: int,
    size: int,
    package_id: int,
    package_name: str,
    type_strings: list[str],
    key_strings: list[str],
    global_strings: list[str],
    sink: Callable[[dict[str, Any]], None] | None,
    diagnostics: list[dict[str, str]],
    type_counts: dict[str, int],
    value_files: dict[tuple[str, str], str] | None = None,
    id_index: dict[int, dict[str, Any]] | None = None,
) -> int:
    type_id = _u8(buf, start + 8)
    flags = _u8(buf, start + 9)
    entry_count = _u32(buf, start + 12)
    entries_start = _u32(buf, start + 16)
    config_size = _u32(buf, start + 20)
    config = _config_string(buf, start + 20, min(config_size, header_size - 20))
    type_name = (
        type_strings[type_id - 1] if 0 < type_id <= len(type_strings) else f"type{type_id}"
    )
    if entry_count > 1_000_000:
        diagnostics.append({
            "code": "resource_entry_count_implausible",
            "message": f"{package_name}/{type_name}: entryCount={entry_count}",
        })
        return 0

    offsets: list[tuple[int, int]] = []
    table_start = start + header_size
    if flags & FLAG_SPARSE:
        for index in range(entry_count):
            entry_index = _u16(buf, table_start + index * 4)
            entry_offset = _u16(buf, table_start + index * 4 + 2) * 4
            offsets.append((entry_index, entry_offset))
    elif flags & FLAG_OFFSET16:
        for index in range(entry_count):
            offsets.append((index, _u16(buf, table_start + index * 2) * 4))
    else:
        for index in range(entry_count):
            offsets.append((index, _u32(buf, table_start + index * 4)))

    emitted = 0
    for entry_index, entry_offset in offsets:
        if entry_offset == NO_ENTRY or entry_offset == 0xFFFF:
            continue
        entry_start = start + entries_start + entry_offset
        if entry_start + 8 > start + size:
            diagnostics.append({
                "code": "resource_entry_out_of_range",
                "message": f"{package_name}/{type_name}[{entry_index}]",
            })
            continue
        entry_flags = _u16(buf, entry_start + 2)
        if entry_flags & FLAG_COMPACT:
            diagnostics.append({
                "code": "resource_compact_entry_unsupported",
                "message": (
                    f"{package_name}/{type_name}[{entry_index}]: compact entry "
                    "layout is not parsed"
                ),
            })
            continue
        key_index = _u32(buf, entry_start + 4)
        key_name = key_strings[key_index] if key_index < len(key_strings) else ""
        value_offset = entry_start + _u16(buf, entry_start)
        if entry_flags & 0x0001:  # COMPLEX: a bag of maps, not a single value
            emitted += 1
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            record = {
                "id": f"{(package_id << 24) | (type_id << 16) | entry_index:#010x}",
                "package": package_name,
                "type": type_name,
                "name": key_name,
                "config": config,
                "value": None,
                "value_type": "complex",
                "reference": None,
                "file": (value_files or {}).get((type_name, key_name)),
            }
            if sink is not None:
                sink(record)
            if id_index is not None:
                _remember(id_index, record, package_id, type_id, entry_index)
            continue
        value_size = _u16(buf, value_offset)
        if value_size < 8:
            diagnostics.append({
                "code": "resource_value_size_invalid",
                "message": f"{package_name}/{type_name}/{key_name}: size={value_size}",
            })
            continue
        value_type = _u8(buf, value_offset + 3)
        data = _u32(buf, value_offset + 4)
        value, value_type_name = _decode_value(value_type, data, global_strings)
        record = {
            "id": f"{(package_id << 24) | (type_id << 16) | entry_index:#010x}",
            "package": package_name,
            "type": type_name,
            "name": key_name,
            "config": config,
            "value": value,
            "value_type": value_type_name,
            "reference": f"@{data:#010x}" if value_type in (
                TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE
            ) else None,
            "file": (value_files or {}).get((type_name, key_name)),
        }
        type_counts[type_name] = type_counts.get(type_name, 0) + 1
        emitted += 1
        if sink is not None:
            sink(record)
        if id_index is not None:
            _remember(id_index, record, package_id, type_id, entry_index)
    return emitted


def parse_resource_table(
    apk_path: str | Path,
    *,
    sink: Callable[[dict[str, Any]], None] | None = None,
    value_files: dict[tuple[str, str], str] | None = None,
    id_index: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Parse ``resources.arsc`` inside an APK and stream one record per value."""
    summary: dict[str, Any] = {
        "status": "failed",
        "source": "resources.arsc",
        "entry_count": 0,
        "type_counts": {},
        "packages": [],
        "configs": [],
        "string_pool_size": 0,
        "diagnostics": [],
    }
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = archive.namelist()
            if "resources.arsc" not in names:
                summary["status"] = "not_found"
                summary["diagnostics"].append({
                    "code": "resource_table_absent",
                    "message": "APK has no resources.arsc",
                })
                return summary
            with archive.open("resources.arsc") as stream:
                buf = stream.read()
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        summary["diagnostics"].append({
            "code": "resource_table_unreadable",
            "message": f"{type(exc).__name__}: {exc}",
        })
        return summary

    try:
        chunk_type, header_size, size = _chunk_header(buf, 0)
        if chunk_type != RES_TABLE_TYPE:
            raise ResourceTableError(f"top chunk is {chunk_type:#06x}, not a table")
        package_count = _u32(buf, 8)
        cursor = header_size
        global_strings: list[str] = []
        if cursor + 8 <= size:
            next_type, _next_header, _next_size = _chunk_header(buf, cursor)
            if next_type == RES_STRING_POOL_TYPE:
                global_strings = parse_string_pool(buf, cursor)
                cursor += _next_size
        summary["string_pool_size"] = len(global_strings)
        package_names: dict[int, str] = {}
        type_counts: dict[str, int] = {}
        total = 0
        while cursor + 8 <= size:
            chunk_type, _chunk_header_size, chunk_size = _chunk_header(buf, cursor)
            if chunk_type == RES_TABLE_PACKAGE_TYPE:
                total += _package_entries(
                    buf, cursor, chunk_size, sink, summary["diagnostics"],
                    type_counts, package_names, global_strings,
                    value_files, id_index,
                )
            cursor += chunk_size
        summary["entry_count"] = total
        summary["type_counts"] = dict(sorted(type_counts.items()))
        summary["packages"] = [
            {"id": f"{package_id:#04x}", "name": name}
            for package_id, name in sorted(package_names.items())
        ]
        summary["package_count"] = package_count
        summary["status"] = "partial" if summary["diagnostics"] else "success"
    except (ResourceTableError, struct.error) as exc:
        summary["diagnostics"].append({
            "code": "resource_table_parse_failed",
            "message": f"{type(exc).__name__}: {exc}",
        })
        summary["status"] = "failed"
    return summary
