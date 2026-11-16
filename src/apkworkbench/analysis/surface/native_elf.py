"""Pure-stdlib ELF reader for native (.so) analysis (native-plan.md N1-N3).

No external dependency: pyelftools/lief/capstone are not installed and are not
approved. This module reads only what it needs, with seek+read windows and
bounds checks on every access, so a 90 MB library never enters RAM whole.

It answers, from file bytes alone:
  - header identity (class, byte order, machine, entry)
  - section table (names, types, offsets, sizes, links)
  - .dynamic (SONAME, NEEDED, RPATH/RUNPATH, FLAGS)
  - .note.gnu.build-id
  - .dynsym/.symtab split into exports (defined global/weak) and imports (undef)

Nothing is guessed: any structural problem returns a reason string from a
closed set and every partial read is recorded in warnings. Callers must treat
``reason`` as data, never as "no symbols".
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

# Section types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_GNU_HASH = 0x6FFFFFF6
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF

SECTION_TYPE_NAMES = {
    SHT_NULL: "NULL",
    SHT_PROGBITS: "PROGBITS",
    SHT_SYMTAB: "SYMTAB",
    SHT_STRTAB: "STRTAB",
    SHT_RELA: "RELA",
    SHT_HASH: "HASH",
    SHT_DYNAMIC: "DYNAMIC",
    SHT_NOTE: "NOTE",
    SHT_NOBITS: "NOBITS",
    SHT_REL: "REL",
    SHT_DYNSYM: "DYNSYM",
    SHT_INIT_ARRAY: "INIT_ARRAY",
    SHT_FINI_ARRAY: "FINI_ARRAY",
    SHT_GNU_HASH: "GNU_HASH",
    SHT_GNU_VERDEF: "GNU_VERDEF",
    SHT_GNU_VERNEED: "GNU_VERNEED",
    SHT_GNU_VERSYM: "GNU_VERSYM",
}

# Dynamic entry tags
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_TEXTREL = 22
DT_BIND_NOW = 24
DT_RUNPATH = 29
DT_FLAGS = 30
DT_GNU_HASH = 0x6FFFFEF5
DT_FLAGS_1 = 0x6FFFFFFB

DYNAMIC_TAG_NAMES = {
    DT_NULL: "NULL",
    DT_NEEDED: "NEEDED",
    DT_PLTRELSZ: "PLTRELSZ",
    DT_HASH: "HASH",
    DT_STRTAB: "STRTAB",
    DT_SYMTAB: "SYMTAB",
    DT_STRSZ: "STRSZ",
    DT_SONAME: "SONAME",
    DT_RPATH: "RPATH",
    16: "SYMBOLIC",
    DT_REL: "REL",
    DT_TEXTREL: "TEXTREL",
    DT_BIND_NOW: "BIND_NOW",
    DT_RUNPATH: "RUNPATH",
    DT_FLAGS: "FLAGS",
    DT_GNU_HASH: "GNU_HASH",
    DT_FLAGS_1: "FLAGS_1",
}

# Program header types
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PROGRAM_TYPE_NAMES = {
    PT_NULL: "NULL",
    PT_LOAD: "LOAD",
    PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP",
    PT_NOTE: "NOTE",
    PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO",
}

# Symbol binding / type / visibility
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_GNU_IFUNC = 10

SYMBOL_BIND_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
SYMBOL_TYPE_NAMES = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "GNU_IFUNC",
}

SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2

# Machine ids seen in Android APKs, plus a few host architectures for fixtures.
MACHINE_NAMES = {
    0: "EM_NONE",
    3: "EM_386",
    8: "EM_MIPS",
    20: "EM_PPC",
    21: "EM_PPC64",
    40: "EM_ARM",
    43: "EM_SPARC_V9",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
    258: "EM_LOONGARCH",
}

ELF_TYPE_NAMES = {
    0: "ET_NONE",
    1: "ET_REL",
    2: "ET_EXEC",
    3: "ET_DYN",
    4: "ET_CORE",
}

# Closed reason set. Callers must not invent new strings at call sites.
PARSE_REASONS = frozenset({
    "not_elf_file",
    "file_stat_failed",
    "file_truncated",
    "unsupported_class",
    "unsupported_data_encoding",
    "header_read_failed",
    "section_header_table_corrupt",
    "program_header_table_corrupt",
    "dynamic_unavailable",
    "symbol_table_corrupt",
    "data_corrupted",
})

# A .so >200 MB symbol table is not real; this is a sanity bound, not a cap on
# Android libraries (largest shipped libs are tens of MB).
MAX_SECTIONS = 4096
MAX_SYMBOLS = 500_000
MAX_STRINGTABLE_BYTES = 32 * 1024 * 1024
MAX_DYNAMIC_ENTRIES = 4096
MAX_NOTES_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ElfHeader:
    elf_class: int  # 1 = ELF32, 2 = ELF64
    class_type: str  # "ELF32" | "ELF64"
    data: int  # 1 = little, 2 = big
    data_encoding: str  # "little" | "big"
    osabi: int
    elf_type: int
    type_name: str
    machine_id: int
    machine: str
    version: int
    entry: int
    phoff: int
    shoff: int
    ehsize: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int


@dataclass(frozen=True)
class ElfSection:
    index: int
    name_offset: int
    name: str
    type: int
    type_name: str
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass(frozen=True)
class ElfSymbol:
    name: str
    name_offset: int
    value: int
    size: int
    bind: int
    bind_name: str
    type: int
    type_name: str
    visibility: int
    shndx: int
    table: str  # "dynsym" | "symtab"

    @property
    def is_export(self) -> bool:
        """Defined symbol exported to other objects (global/weak, not SECTION/FILE)."""
        return (
            self.shndx != SHN_UNDEF
            and self.bind in (STB_GLOBAL, STB_WEAK)
            and self.type in (STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_COMMON, STT_TLS, STT_GNU_IFUNC)
            and self.name != ""
        )

    @property
    def is_import(self) -> bool:
        """Undefined symbol this object requires from a dependency."""
        return self.shndx == SHN_UNDEF and self.name != "" and self.bind in (
            STB_GLOBAL, STB_WEAK,
        )


@dataclass
class ElfDynamic:
    soname: str | None = None
    needed: list[str] = field(default_factory=list)
    rpath: str | None = None
    runpath: str | None = None
    flags: int | None = None
    flags_1: int | None = None
    strtab_vaddr: int | None = None
    strtab_size: int | None = None
    symtab_vaddr: int | None = None
    gnu_hash_vaddr: int | None = None
    entries: list[dict[str, object]] = field(default_factory=list)


@dataclass(frozen=True)
class ElfNote:
    name: str
    type_id: int
    description: bytes


@dataclass
class ElfParseResult:
    path: str
    reason: str = ""
    header: ElfHeader | None = None
    sections: list[ElfSection] = field(default_factory=list)
    program_headers: list[dict[str, int]] = field(default_factory=list)
    exports: list[ElfSymbol] = field(default_factory=list)
    imports: list[ElfSymbol] = field(default_factory=list)
    dynamic: ElfDynamic | None = None
    build_id: str | None = None
    notes: list[ElfNote] = field(default_factory=list)
    warnings: list[dict[str, object]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.header is not None and self.reason == ""

    def section(self, name: str) -> ElfSection | None:
        return next((item for item in self.sections if item.name == name), None)


class _Reader:
    """Bounds-checked random-access reads over an open file."""

    def __init__(self, handle, size: int):
        self._handle = handle
        self.size = size

    def read(self, offset: int, length: int) -> bytes | None:
        if offset < 0 or length < 0 or offset + length > self.size:
            return None
        self._handle.seek(offset)
        data = self._handle.read(length)
        if len(data) != length:
            return None
        return data


def _cstring(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def parse_elf(path: str | Path) -> ElfParseResult:
    """Parse one ELF file. Never raises for malformed input; returns a reason."""
    result = ElfParseResult(path=str(path))
    target = Path(path)
    try:
        size = target.stat().st_size
    except OSError:
        result.reason = "file_stat_failed"
        return result

    try:
        handle = target.open("rb")
    except OSError:
        result.reason = "file_stat_failed"
        return result

    with handle:
        reader = _Reader(handle, size)
        ident = reader.read(0, 16)
        if ident is None or len(ident) < 16:
            result.reason = "file_truncated"
            return result
        if ident[:4] != ELF_MAGIC:
            result.reason = "not_elf_file"
            return result

        elf_class = ident[4]
        data = ident[5]
        if elf_class == 1:
            class_type = "ELF32"
        elif elf_class == 2:
            class_type = "ELF64"
        else:
            result.reason = "unsupported_class"
            return result
        if data == 1:
            data_encoding, endian = "little", "<"
        elif data == 2:
            data_encoding, endian = "big", ">"
        else:
            result.reason = "unsupported_data_encoding"
            return result

        if class_type == "ELF32":
            raw = reader.read(16, 36)
            if raw is None:
                result.reason = "file_truncated"
                return result
            try:
                (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, _e_flags,
                 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
                 e_shstrndx) = struct.unpack(endian + "HHIIIIIHHHHHH", raw)
            except struct.error:
                result.reason = "header_read_failed"
                return result
        else:
            raw = reader.read(16, 48)
            if raw is None:
                result.reason = "file_truncated"
                return result
            try:
                (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, _e_flags,
                 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
                 e_shstrndx) = struct.unpack(endian + "HHIQQQIHHHHHH", raw)
            except struct.error:
                result.reason = "header_read_failed"
                return result

        result.header = ElfHeader(
            elf_class=elf_class,
            class_type=class_type,
            data=data,
            data_encoding=data_encoding,
            osabi=ident[7],
            elf_type=e_type,
            type_name=ELF_TYPE_NAMES.get(e_type, f"ET_{e_type}"),
            machine_id=e_machine,
            machine=MACHINE_NAMES.get(e_machine, f"EM_UNKNOWN_{e_machine}"),
            version=e_version,
            entry=e_entry,
            phoff=e_phoff,
            shoff=e_shoff,
            ehsize=e_ehsize,
            phentsize=e_phentsize,
            phnum=e_phnum,
            shentsize=e_shentsize,
            shnum=e_shnum,
            shstrndx=e_shstrndx,
        )

        _read_program_headers(reader, result, endian)
        _read_sections(reader, result, endian)
        _read_notes(reader, result, endian)
        _read_dynamic(reader, result, endian)
        _read_symbols(reader, result, endian)
    return result


def _read_program_headers(reader: _Reader, result: ElfParseResult, endian: str) -> None:
    header = result.header
    assert header is not None
    if not header.phoff or not header.phnum:
        return
    expected = 32 if header.class_type == "ELF32" else 56
    if header.phentsize < expected:
        result.warnings.append({
            "code": "program_header_entry_size_invalid",
            "message": f"phentsize={header.phentsize} expected>={expected}",
        })
        return
    table = reader.read(header.phoff, header.phentsize * header.phnum)
    if table is None:
        result.warnings.append({
            "code": "program_header_table_truncated",
            "message": f"phoff={header.phoff} phnum={header.phnum}",
        })
        return
    fmt = endian + ("IIIIIIII" if header.class_type == "ELF32" else "IIQQQQQQ")
    for index in range(header.phnum):
        chunk = table[index * header.phentsize:index * header.phentsize + expected]
        if len(chunk) != expected:
            break
        try:
            fields = struct.unpack(fmt, chunk)
        except struct.error:
            break
        if header.class_type == "ELF32":
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = fields
        else:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = fields
        result.program_headers.append({
            "index": index,
            "type": p_type,
            "type_name": PROGRAM_TYPE_NAMES.get(p_type, f"PT_{p_type}"),
            "offset": p_offset,
            "vaddr": p_vaddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "flags": p_flags,
            "align": p_align,
        })


def _read_sections(reader: _Reader, result: ElfParseResult, endian: str) -> None:
    header = result.header
    assert header is not None
    if not header.shoff:
        result.warnings.append({
            "code": "section_header_table_absent",
            "message": "e_shoff=0 (stripped or packed library)",
        })
        return
    entry_size = 40 if header.class_type == "ELF32" else 64
    if header.shentsize < entry_size:
        result.warnings.append({
            "code": "section_header_entry_size_invalid",
            "message": f"shentsize={header.shentsize} expected>={entry_size}",
        })
        return
    shnum = header.shnum
    if shnum == 0:
        # Extended numbering: section 0's sh_size holds the real count.
        first = reader.read(header.shoff, entry_size)
        if first is None:
            result.warnings.append({
                "code": "section_header_table_truncated",
                "message": "cannot read section 0 for extended numbering",
            })
            return
        shnum = _unpack_section(endian, header.class_type, first).size
        if shnum <= 0 or shnum > MAX_SECTIONS:
            result.warnings.append({
                "code": "section_header_count_invalid",
                "message": f"extended shnum={shnum}",
            })
            return
    if shnum > MAX_SECTIONS:
        result.warnings.append({
            "code": "section_header_count_invalid",
            "message": f"shnum={shnum} exceeds sanity bound {MAX_SECTIONS}",
        })
        return
    table = reader.read(header.shoff, header.shentsize * shnum)
    if table is None:
        result.warnings.append({
            "code": "section_header_table_truncated",
            "message": f"shoff={header.shoff} shnum={shnum}",
        })
        return
    raw_sections = []
    for index in range(shnum):
        start = index * header.shentsize
        chunk = table[start:start + entry_size]
        if len(chunk) != entry_size:
            break
        raw_sections.append(_unpack_section(endian, header.class_type, chunk))

    # Section name string table (needed for readable names).
    names_blob = b""
    if 0 <= header.shstrndx < len(raw_sections):
        shstr = raw_sections[header.shstrndx]
        if shstr.type == SHT_STRTAB or shstr.size:
            length = min(shstr.size, MAX_STRINGTABLE_BYTES)
            blob = reader.read(shstr.offset, length)
            if blob is not None:
                names_blob = blob
            else:
                result.warnings.append({
                    "code": "section_name_table_unreadable",
                    "message": f"shstrtab offset={shstr.offset} size={shstr.size}",
                })

    for index, raw in enumerate(raw_sections):
        name = _cstring(names_blob, raw.name_offset) if names_blob else ""
        result.sections.append(ElfSection(
            index=index,
            name_offset=raw.name_offset,
            name=name,
            type=raw.type,
            type_name=SECTION_TYPE_NAMES.get(raw.type, f"SHT_{raw.type:#x}"),
            flags=raw.flags,
            addr=raw.addr,
            offset=raw.offset,
            size=raw.size,
            link=raw.link,
            info=raw.info,
            addralign=raw.addralign,
            entsize=raw.entsize,
        ))


@dataclass(frozen=True)
class _RawSection:
    name_offset: int
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


def _unpack_section(endian: str, class_type: str, chunk: bytes) -> _RawSection:
    if class_type == "ELF32":
        fields = struct.unpack(endian + "IIIIIIIIII", chunk)
        (name_offset, type_, flags, addr, offset, size, link, info, addralign,
         entsize) = fields
    else:
        fields = struct.unpack(endian + "IIQQQQIIQQ", chunk)
        (name_offset, type_, flags, addr, offset, size, link, info, addralign,
         entsize) = fields
    return _RawSection(
        name_offset=name_offset, type=type_, flags=flags, addr=addr,
        offset=offset, size=size, link=link, info=info,
        addralign=addralign, entsize=entsize,
    )


def _read_notes(reader: _Reader, result: ElfParseResult, endian: str) -> None:
    for section in result.sections:
        if section.type != SHT_NOTE:
            continue
        length = min(section.size, MAX_NOTES_BYTES)
        blob = reader.read(section.offset, length)
        if blob is None:
            result.warnings.append({
                "code": "note_section_unreadable",
                "message": f"{section.name or 'note'} offset={section.offset} size={section.size}",
            })
            continue
        offset = 0
        while offset + 12 <= len(blob):
            try:
                namesz, descsz, type_id = struct.unpack_from(endian + "III", blob, offset)
            except struct.error:
                break
            offset += 12
            name_end = offset + namesz
            if name_end > len(blob):
                break
            name = blob[offset:name_end].rstrip(b"\x00").decode("utf-8", errors="replace")
            offset = name_end
            offset += (-offset) % 4
            desc_end = offset + descsz
            if desc_end > len(blob):
                break
            description = blob[offset:desc_end]
            offset = desc_end
            offset += (-offset) % 4
            note = ElfNote(name=name, type_id=type_id, description=description)
            result.notes.append(note)
            if name == "GNU" and type_id == 3 and description:
                result.build_id = description.hex()


def _read_dynamic(reader: _Reader, result: ElfParseResult, endian: str) -> None:
    header = result.header
    assert header is not None
    section = next((item for item in result.sections if item.type == SHT_DYNAMIC), None)
    if section is None:
        # Fall back to PT_DYNAMIC location; strtab resolution still needs sections.
        program = next(
            (item for item in result.program_headers if item["type"] == PT_DYNAMIC), None
        )
        if program is None:
            result.warnings.append({
                "code": "dynamic_section_absent",
                "message": "no SHT_DYNAMIC section and no PT_DYNAMIC program header",
            })
            return
        offset, size, entsize = program["offset"], program["filesz"], 16 if header.class_type == "ELF64" else 8
        strtab_section = None
    else:
        offset, size = section.offset, section.size
        entsize = section.entsize or (16 if header.class_type == "ELF64" else 8)
        strtab_section = (
            result.sections[section.link]
            if 0 <= section.link < len(result.sections) else None
        )

    if entsize < (16 if header.class_type == "ELF64" else 8):
        result.warnings.append({
            "code": "dynamic_entry_size_invalid",
            "message": f"entsize={entsize}",
        })
        return
    blob = reader.read(offset, min(size, MAX_DYNAMIC_ENTRIES * entsize))
    if blob is None:
        result.warnings.append({
            "code": "dynamic_section_unreadable",
            "message": f"offset={offset} size={size}",
        })
        return

    strings = b""
    if strtab_section is not None:
        strings = reader.read(strtab_section.offset, min(strtab_section.size, MAX_STRINGTABLE_BYTES)) or b""

    dynamic = ElfDynamic()
    count = len(blob) // entsize
    fmt = endian + ("qQ" if header.class_type == "ELF64" else "iI")
    for index in range(min(count, MAX_DYNAMIC_ENTRIES)):
        try:
            tag, value = struct.unpack_from(fmt, blob, index * entsize)
        except struct.error:
            break
        dynamic.entries.append({
            "tag": tag,
            "tag_name": DYNAMIC_TAG_NAMES.get(tag, f"DT_{tag:#x}"),
            "value": value,
        })
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            dynamic.needed.append(_cstring(strings, value))
        elif tag == DT_SONAME:
            dynamic.soname = _cstring(strings, value)
        elif tag == DT_RPATH:
            dynamic.rpath = _cstring(strings, value)
        elif tag == DT_RUNPATH:
            dynamic.runpath = _cstring(strings, value)
        elif tag == DT_FLAGS:
            dynamic.flags = value
        elif tag == DT_FLAGS_1:
            dynamic.flags_1 = value
        elif tag == DT_STRTAB:
            dynamic.strtab_vaddr = value
        elif tag == DT_STRSZ:
            dynamic.strtab_size = value
        elif tag == DT_SYMTAB:
            dynamic.symtab_vaddr = value
        elif tag == DT_GNU_HASH:
            dynamic.gnu_hash_vaddr = value
    result.dynamic = dynamic


def _read_symbols(reader: _Reader, result: ElfParseResult, endian: str) -> None:
    header = result.header
    assert header is not None
    for section in result.sections:
        if section.type not in (SHT_DYNSYM, SHT_SYMTAB):
            continue
        table_name = "dynsym" if section.type == SHT_DYNSYM else "symtab"
        entry_size = 16 if header.class_type == "ELF32" else 24
        if section.entsize and section.entsize < entry_size:
            result.warnings.append({
                "code": "symbol_entry_size_invalid",
                "message": f"{table_name} entsize={section.entsize}",
            })
            continue
        count = section.size // entry_size
        if count <= 0:
            continue
        if count > MAX_SYMBOLS:
            result.warnings.append({
                "code": "symbol_count_invalid",
                "message": f"{table_name} count={count} exceeds {MAX_SYMBOLS}",
            })
            continue
        strings = b""
        if 0 <= section.link < len(result.sections):
            strtab = result.sections[section.link]
            strings = reader.read(strtab.offset, min(strtab.size, MAX_STRINGTABLE_BYTES)) or b""
        blob = reader.read(section.offset, count * entry_size)
        if blob is None:
            result.warnings.append({
                "code": "symbol_table_unreadable",
                "message": f"{table_name} offset={section.offset} size={section.size}",
            })
            continue
        unresolved_names = 0
        for index in range(count):
            chunk = blob[index * entry_size:(index + 1) * entry_size]
            if len(chunk) != entry_size:
                break
            if header.class_type == "ELF32":
                name_offset, value, sym_size, info, other, shndx = struct.unpack(
                    endian + "IIIBBH", chunk
                )
            else:
                name_offset, info, other, shndx, value, sym_size = struct.unpack(
                    endian + "IBBHQQ", chunk
                )
            if index == 0:
                continue  # null symbol, never a real export/import
            bind = info >> 4
            sym_type = info & 0xF
            symbol = ElfSymbol(
                name=_cstring(strings, name_offset),
                name_offset=name_offset,
                value=value,
                size=sym_size,
                bind=bind,
                bind_name=SYMBOL_BIND_NAMES.get(bind, f"BIND_{bind}"),
                type=sym_type,
                type_name=SYMBOL_TYPE_NAMES.get(sym_type, f"TYPE_{sym_type}"),
                visibility=other & 0x3,
                shndx=shndx,
                table=table_name,
            )
            if symbol.is_export:
                result.exports.append(symbol)
            elif symbol.is_import:
                result.imports.append(symbol)
            elif symbol.name == "" and name_offset:
                unresolved_names += 1
        if unresolved_names:
            result.warnings.append({
                "code": "symbol_name_unresolved",
                "message": f"{table_name}: {unresolved_names} symbol name(s) point outside {table_name} string table",
            })
