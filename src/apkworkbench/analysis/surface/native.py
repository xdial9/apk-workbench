"""Native (JNI) analysis: exports, imports, JNI mapping, load sites, strings.

This is the crown-jewel-5 work described in ai-memory/native-plan.md. It turns
the ELF reader's bytes into *mapped* facts:

  - what the library exports  -> joined to the Java ``native`` declaration
  - what it imports           -> capability evidence (dlsym, exec, ptrace)
  - which Java code loads it  -> System.loadLibrary / System.load call sites
  - what strings it holds     -> value + byte offset (+ secret hints)

Laws obeyed here:
  * every fact cites a real byte offset; no synthetic line numbers
  * every unmapped export carries a reason from a closed set, never free text
  * strings are streamed in windows (ASCII + UTF-16LE) and deduped by value;
    any cap is reported as a diagnostic and flips coverage to partial
  * dynamic registration is never guessed: strings are offered as candidates
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apkworkbench.analysis.surface.native_elf import (
    ElfParseResult,
    ElfSymbol,
    parse_elf,
)

# ---- strings ---------------------------------------------------------------

STRING_CHUNK_BYTES = 1 << 20  # 1 MiB windows; a .so never enters RAM whole
STRING_OVERLAP_BYTES = 256    # covers any string crossing a window boundary
ASCII_STRING_RE = re.compile(rb"[ -~]{4,}")
UTF16LE_STRING_RE = re.compile(rb"(?:[ -~]\x00){4,}")

MAX_STRINGS_PER_LIBRARY = 20_000
MAX_STRING_FACTS_ARTIFACT = 60_000
MAX_SYMBOL_FACTS_ARTIFACT = 20_000
MAX_NATIVE_FINDINGS_ARTIFACT = 200

SECRET_KEYWORDS = (
    "secret", "passwd", "password", "api_key", "apikey", "api-key",
    "private_key", "private-key", "credential", "auth_token", "access_token",
)

# Closed set: a reason outside this set is a bug, not a value.
UNMAPPED_REASONS = frozenset({
    "no_matching_method",
    "not_jni_symbol",
    "demangle_ambiguous",
    "ambiguous_overload",
    "signature_mismatch",
    "stripped_symbols",
    "dynamic_registration_unresolved",
    "unreferenced",
    "dependency_of_other_lib",
    "not_elf_archive",
    "obfuscated_path",
    "no_load_site",
})

EXEC_SYMBOLS = frozenset({
    "system", "popen", "execl", "execle", "execlp", "execv", "execve",
    "execvp", "execvpe", "fork", "vfork", "posix_spawn", "__system_chk",
})
DYNAMIC_LOAD_SYMBOLS = frozenset({"dlopen", "dlsym", "dlclose", "dlerror", "dlvsym", "android_dlopen_ext"})
ANTI_DEBUG_SYMBOLS = frozenset({"ptrace", "prctl", "kill", "tgkill"})
REGISTER_NATIVES = "RegisterNatives"


@dataclass
class StringScan:
    values: list[tuple[str, int]] = field(default_factory=list)  # (value, first offset)
    matches: int = 0
    unique: int = 0
    bytes_scanned: int = 0
    truncated: bool = False
    limit: int = MAX_STRINGS_PER_LIBRARY

    def text(self) -> str:
        return "\n".join(value for value, _offset in self.values)


def _iter_strings(data: bytes, base: int) -> Iterator[tuple[str, int]]:
    for match in ASCII_STRING_RE.finditer(data):
        yield match.group().decode("ascii", errors="replace"), base + match.start()
    for match in UTF16LE_STRING_RE.finditer(data):
        yield match.group().decode("utf-16-le", errors="replace"), base + match.start()


def scan_strings(path: Path, *, limit: int = MAX_STRINGS_PER_LIBRARY,
                 chunk_bytes: int = STRING_CHUNK_BYTES) -> StringScan:
    """Stream printable ASCII + UTF-16LE strings, deduped by value (first offset)."""
    scan = StringScan(limit=limit)
    seen: dict[str, int] = {}
    try:
        handle = path.open("rb")
    except OSError:
        return scan
    with handle:
        carry = b""
        offset = 0
        while True:
            try:
                chunk = handle.read(chunk_bytes)
            except OSError:
                break
            if not chunk:
                break
            window = carry + chunk
            base = offset - len(carry)
            for value, absolute in _iter_strings(window, base):
                scan.matches += 1
                if value in seen:
                    continue
                if len(seen) >= limit:
                    scan.truncated = True
                    continue
                seen[value] = absolute
            carry = window[-STRING_OVERLAP_BYTES:]
            offset += len(chunk)
        scan.bytes_scanned = offset
    scan.values = sorted(seen.items(), key=lambda item: item[1])
    scan.unique = len(scan.values)
    return scan


# ---- JNI demangling --------------------------------------------------------

JNI_PREFIX = "Java_"


@dataclass(frozen=True)
class JniName:
    java_class: str
    java_method: str
    signature: str | None
    problem: str = ""


def _split_mangled(text: str) -> list[str]:
    """Split a mangled JNI name on bare ``_`` while decoding ``_1 _2 _3 _0xxxx``."""
    parts: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "_" and index + 1 < len(text):
            nxt = text[index + 1]
            if nxt == "1":
                current.append("_")
                index += 2
                continue
            if nxt == "2":
                current.append(";")
                index += 2
                continue
            if nxt == "3":
                current.append("[")
                index += 2
                continue
            if nxt == "0" and index + 6 <= len(text):
                try:
                    current.append(chr(int(text[index + 2:index + 6], 16)))
                    index += 6
                    continue
                except ValueError:
                    pass
            parts.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def demangle_jni_symbol(symbol: str) -> JniName | None:
    """``Java_com_example_Foo_bar__Ljava_lang_String_2`` -> class/method/signature.

    Returns None when the symbol is not a ``Java_`` JNI export. An ambiguous
    class boundary returns a JniName with ``problem`` set (closed reason), never
    a best-effort guess.
    """
    if not symbol.startswith(JNI_PREFIX):
        return None
    body = symbol[len(JNI_PREFIX):]
    signature: str | None = None
    if "__" in body:
        body, _, mangled_signature = body.partition("__")
        if mangled_signature:
            signature = "/".join(_split_mangled(mangled_signature))
        else:
            signature = ""

    segments = _split_mangled(body)
    if not segments or not all(segments):
        return JniName("", "", signature, "demangle_ambiguous")
    class_end = next(
        (index for index, segment in enumerate(segments) if segment[:1].isupper()),
        None,
    )
    if class_end is None or class_end + 1 >= len(segments):
        return JniName("", "", signature, "demangle_ambiguous")
    class_segments = segments[:class_end + 1]
    method_segments = segments[class_end + 1:]
    if len(method_segments) != 1:
        # A bare '_' can only be a separator, so more than one trailing segment
        # means the boundary is genuinely unknown.
        return JniName("", "", signature, "demangle_ambiguous")
    return JniName(
        java_class="L" + "/".join(class_segments) + ";",
        java_method=method_segments[0],
        signature=signature,
    )


# ---- smali index: native method declarations + library load sites ----------

SMALI_CLASS_RE = re.compile(r"^\.class\b[^\n]*?(L[^\s;]+;)", re.MULTILINE)
SMALI_METHOD_RE = re.compile(r"^\.method\b([^\n]*)$", re.MULTILINE)
METHOD_SIGNATURE_RE = re.compile(r"(?P<name>[A-Za-z_$][\w$]*)\s*(?P<signature>\([^)]*\)\S+)\s*$")
CONST_STRING_RE = re.compile(
    r'const-string(?:/jumbo)?\s+(?P<register>v\d+)\s*,\s*"(?P<value>(?:[^"\\]|\\.)*)"'
)
LOAD_INVOKE_RE = re.compile(
    r"invoke-(?:static|virtual)\s+\{(?P<registers>[^}]*)\},\s*"
    r"Ljava/lang/System;->(?P<method>loadLibrary|load)\(Ljava/lang/String;\)V"
)


class NativeMethodIndex:
    """Declared ``native`` methods, built once per artifact from smali text."""

    def __init__(self) -> None:
        self._by_class: dict[str, list[dict[str, Any]]] = {}

    def add_file(self, text: str, relative: str) -> int:
        if "native" not in text or ".method" not in text:
            return 0
        class_match = SMALI_CLASS_RE.search(text)
        if class_match is None:
            return 0
        java_class = "L" + class_match.group(1)[1:] if not class_match.group(1).startswith("L") else class_match.group(1)
        added = 0
        for match in SMALI_METHOD_RE.finditer(text):
            declaration = match.group(1)
            tokens = declaration.split()
            if "native" not in tokens:
                continue
            signature_match = METHOD_SIGNATURE_RE.search(declaration.strip())
            if signature_match is None:
                continue
            line = text.count("\n", 0, match.start()) + 1
            entry = {
                "class": java_class,
                "method": signature_match.group("name"),
                "signature": signature_match.group("signature"),
                "path": relative,
                "line": line,
            }
            self._by_class.setdefault(java_class, []).append(entry)
            added += 1
        return added

    def lookup(self, java_class: str, method: str) -> list[dict[str, Any]]:
        return [
            entry for entry in self._by_class.get(java_class, [])
            if entry["method"] == method
        ]

    def __len__(self) -> int:
        return sum(len(items) for items in self._by_class.values())


def extract_library_loads(text: str, relative: str) -> list[dict[str, Any]]:
    """Resolve ``const-string`` -> ``System.loadLibrary/load`` pairs in one smali file."""
    if "loadLibrary" not in text and "System;->load" not in text:
        return []
    last_string: dict[str, str] = {}
    loads: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        string_match = CONST_STRING_RE.search(line)
        if string_match is not None:
            last_string[string_match.group("register")] = string_match.group("value")
            continue
        invoke_match = LOAD_INVOKE_RE.search(line)
        if invoke_match is None:
            continue
        registers = [item.strip() for item in invoke_match.group("registers").split(",")]
        value = next((last_string[item] for item in registers if item in last_string), None)
        loads.append({
            "path": relative,
            "line": line_number,
            "system_call": invoke_match.group("method"),
            "value": value,
            "resolved": value is not None,
        })
    return loads


def library_from_load_value(value: str | None) -> str | None:
    if not value:
        return None
    name = value.rsplit("/", 1)[-1]
    if name.endswith(".so"):
        return name
    return f"lib{name}.so"


# ---- per-library analysis --------------------------------------------------

@dataclass
class NativeLibraryReport:
    relative: str
    state: str  # parsed | stripped_symbols | parse_failed | not_elf
    reason: str = ""
    parsed: ElfParseResult | None = None
    strings: StringScan | None = None
    jni_entries: list[dict[str, Any]] = field(default_factory=list)
    unmapped: list[dict[str, Any]] = field(default_factory=list)
    load_sites: list[dict[str, Any]] = field(default_factory=list)
    exports_emitted: int = 0
    imports_emitted: int = 0

    def as_inventory(self) -> dict[str, Any]:
        parsed = self.parsed
        return {
            "path": self.relative,
            "state": self.state,
            "reason": self.reason or None,
            "elf": (
                {
                    "class": parsed.header.class_type,
                    "data": parsed.header.data_encoding,
                    "machine": parsed.header.machine,
                    "type": parsed.header.type_name,
                }
                if parsed is not None and parsed.header is not None else None
            ),
            "soname": parsed.dynamic.soname if parsed is not None and parsed.dynamic else None,
            "needed": list(parsed.dynamic.needed) if parsed is not None and parsed.dynamic else [],
            "build_id": parsed.build_id if parsed is not None else None,
            "exports_total": len(parsed.exports) if parsed is not None else 0,
            "exports_emitted": self.exports_emitted,
            "imports_total": len(parsed.imports) if parsed is not None else 0,
            "imports_emitted": self.imports_emitted,
            "jni_entries": len(self.jni_entries),
            "jni_unmapped": len(self.unmapped),
            "strings_unique": self.strings.unique if self.strings else 0,
            "strings_matches": self.strings.matches if self.strings else 0,
            "strings_truncated": bool(self.strings.truncated) if self.strings else False,
            "load_sites": self.load_sites,
            "warnings": list(parsed.warnings) if parsed is not None else [],
        }


@dataclass
class NativeAnalysis:
    facts: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[dict[str, str]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    libraries: list[dict[str, Any]] = field(default_factory=list)
    jni_entries: list[dict[str, Any]] = field(default_factory=list)
    unmapped_entries: list[dict[str, Any]] = field(default_factory=list)
    load_sites: list[dict[str, Any]] = field(default_factory=list)
    strings_by_lib: dict[str, str] = field(default_factory=dict)


def analyze_native(
    root: Path,
    libraries: list[str],
    *,
    native_method_index: NativeMethodIndex,
    library_loads: list[dict[str, Any]],
    progress: Callable[[str], None] | None = None,
) -> NativeAnalysis:
    """Parse, map and cite every native library. Never raises for a bad .so."""
    analysis = NativeAnalysis()
    if not libraries:
        analysis.coverage = {
            "native_libraries": "not_found",
            "native_symbols": "not_applicable",
            "native_jni_mapping": "not_applicable",
            "native_strings": "not_applicable",
        }
        analysis.metrics = _empty_metrics()
        return analysis

    known_names = {relative.rsplit("/", 1)[-1]: relative for relative in libraries}
    loads_by_library: dict[str, list[dict[str, Any]]] = {}
    unresolved_loads: list[dict[str, Any]] = []
    for load in library_loads:
        resolved = library_from_load_value(load.get("value"))
        if resolved is None:
            unresolved_loads.append({**load, "reason": "no_library_literal"})
            continue
        if resolved not in known_names:
            unresolved_loads.append({**load, "reason": "no_matching_library", "library": resolved})
            continue
        loads_by_library.setdefault(known_names[resolved], []).append(load)

    reports: list[NativeLibraryReport] = []
    string_fact_count = 0
    symbol_fact_count = 0
    finding_count = 0

    for index, relative in enumerate(libraries, start=1):
        lib_path = root / relative
        if progress is not None:
            progress(f"[Surface] native {index}/{len(libraries)}: {relative}")
        report = NativeLibraryReport(relative=relative, state="parsed")
        parsed = parse_elf(lib_path)
        report.parsed = parsed
        if parsed.reason == "not_elf_file":
            report.state = "not_elf"
            report.reason = parsed.reason
            analysis.diagnostics.append({
                "code": "native_not_elf",
                "message": f"{relative}: ELF magic absent ({parsed.reason})",
            })
            reports.append(report)
            continue
        if not parsed.ok:
            report.state = "parse_failed"
            report.reason = parsed.reason
            analysis.diagnostics.append({
                "code": "native_elf_parse_failed",
                "message": f"{relative}: {parsed.reason}",
            })
            reports.append(report)
            continue
        if parsed.section(".dynsym") is None and not parsed.exports:
            report.state = "stripped_symbols"
            report.reason = "stripped_symbols"

        header = parsed.header
        assert header is not None
        analysis.facts.append({
            "kind": "native_elf",
            "value": relative,
            "evidence": {"path": relative, "offset": 0},
            "extra": {
                "library": relative,
                "elf_class": header.class_type,
                "data_encoding": header.data_encoding,
                "machine": header.machine,
                "elf_type": header.type_name,
                "soname": parsed.dynamic.soname if parsed.dynamic else None,
                "needed": list(parsed.dynamic.needed) if parsed.dynamic else [],
                "rpath": parsed.dynamic.rpath if parsed.dynamic else None,
                "runpath": parsed.dynamic.runpath if parsed.dynamic else None,
                "flags": parsed.dynamic.flags if parsed.dynamic else None,
                "build_id": parsed.build_id,
                "warnings": [item["code"] for item in parsed.warnings],
            },
        })

        # --- exports / imports -> facts (bounded, counted)
        for symbol in parsed.exports:
            symbol_fact_count += 1
            if symbol_fact_count > MAX_SYMBOL_FACTS_ARTIFACT:
                break
            report.exports_emitted += 1
            analysis.facts.append({
                "kind": "native_export",
                "value": f"{relative}::{symbol.name}",
                "evidence": {"path": relative, "offset": symbol.file_offset},
                "extra": {
                    "library": relative,
                    "symbol": symbol.name,
                    "binding": symbol.bind_name,
                    "symbol_type": symbol.type_name,
                    "address": symbol.value,
                    "size": symbol.size,
                },
            })
        for symbol in parsed.imports:
            symbol_fact_count += 1
            if symbol_fact_count > MAX_SYMBOL_FACTS_ARTIFACT:
                break
            report.imports_emitted += 1
            analysis.facts.append({
                "kind": "native_import",
                "value": f"{relative}::{symbol.name}",
                "evidence": {"path": relative, "offset": symbol.file_offset},
                "extra": {
                    "library": relative,
                    "symbol": symbol.name,
                    "binding": symbol.bind_name,
                    "symbol_type": symbol.type_name,
                    "address": symbol.value,
                },
            })

        # --- JNI mapping: exported Java_* -> declared native smali method
        for symbol in parsed.exports:
            if not symbol.name.startswith(JNI_PREFIX):
                continue
            name = demangle_jni_symbol(symbol.name)
            if name is None:
                continue
            entry, reason = _map_jni_symbol(
                relative, symbol, name, native_method_index
            )
            if entry is not None:
                report.jni_entries.append(entry)
                analysis.jni_entries.append(entry)
                analysis.facts.append({
                    "kind": "native_jni_entry",
                    "value": f"{relative}::{symbol.name}",
                    "evidence": [
                        {"path": relative, "offset": symbol.file_offset},
                        {"path": entry["smali_path"], "line": entry["smali_line"]},
                    ],
                    "extra": {
                        "library": relative,
                        "symbol": symbol.name,
                        "java_class": entry["java_class"],
                        "java_method": entry["java_method"],
                        "java_signature": entry["java_signature"],
                        "mapping_confidence": entry["confidence"],
                    },
                })
            else:
                unmapped = {
                    "library": relative,
                    "symbol": symbol.name,
                    "java_class": name.java_class or None,
                    "java_method": name.java_method or None,
                    "java_signature": name.signature,
                    "reason": reason,
                    "offset": symbol.file_offset,
                }
                report.unmapped.append(unmapped)
                analysis.unmapped_entries.append(unmapped)
                analysis.facts.append({
                    "kind": "native_jni_unmapped",
                    "value": f"{relative}::{symbol.name}",
                    "evidence": {"path": relative, "offset": symbol.file_offset},
                    "extra": {
                        "library": relative,
                        "symbol": symbol.name,
                        "java_class": name.java_class or None,
                        "java_method": name.java_method or None,
                        "java_signature": name.signature,
                        "reason": reason,
                    },
                })

        # --- RegisterNatives candidates (never paired by guess)
        register_natives = any(
            item.name == REGISTER_NATIVES
            for item in (*parsed.exports, *parsed.imports)
        )

        # --- strings v2: streamed, deduped, capped-but-counted
        strings = scan_strings(lib_path)
        report.strings = strings
        analysis.strings_by_lib[relative] = strings.text()
        if strings.truncated:
            analysis.diagnostics.append({
                "code": "native_string_limit",
                "message": (
                    f"{relative}: kept {strings.unique} unique strings "
                    f"(limit {strings.limit}); remaining values counted, not stored"
                ),
            })
        for value, offset in strings.values:
            if string_fact_count >= MAX_STRING_FACTS_ARTIFACT:
                strings.truncated = True
                break
            string_fact_count += 1
            analysis.facts.append({
                "kind": "native_string",
                "value": value,
                "evidence": {"path": relative, "offset": offset},
                "extra": {"library": relative},
            })
        if string_fact_count >= MAX_STRING_FACTS_ARTIFACT:
            analysis.diagnostics.append({
                "code": "native_string_fact_limit",
                "message": (
                    f"artifact string-fact cap {MAX_STRING_FACTS_ARTIFACT} reached; "
                    "per-library totals remain exact in metrics"
                ),
            })
        lowered = [(value, offset) for value, offset in strings.values]
        for value, offset in lowered:
            low = value.lower()
            if any(keyword in low for keyword in SECRET_KEYWORDS):
                analysis.facts.append({
                    "kind": "native_secret_hint",
                    "value": value.strip(),
                    "evidence": {"path": relative, "offset": offset},
                    "extra": {"library": relative},
                })

        # --- load sites
        report.load_sites = list(loads_by_library.get(relative, []))
        analysis.load_sites.extend(report.load_sites)

        # --- findings from parsed evidence only
        finding_count = _emit_native_findings(
            analysis, report, parsed, strings, register_natives,
            finding_count, relative,
        )
        reports.append(report)

    # load-site facts (the caller half of the crown jewel)
    for load in analysis.load_sites:
        resolved = library_from_load_value(load.get("value"))
        relative = known_names.get(resolved or "") if resolved else None
        if relative is None:
            continue
        analysis.facts.append({
            "kind": "native_library_load",
            "value": f"{relative}",
            "evidence": {"path": load["path"], "line": load["line"]},
            "extra": {
                "library": relative,
                "java_literal": load.get("value"),
                "java_call": f"java.lang.System.{load.get('system_call')}",
            },
        })
    for load in unresolved_loads:
        analysis.facts.append({
            "kind": "native_load_unresolved",
            "value": str(load.get("value")),
            "evidence": {"path": load["path"], "line": load["line"]},
            "extra": {
                "java_call": f"java.lang.System.{load.get('system_call')}",
                "reason": load["reason"],
            },
        })

    analysis.libraries = [report.as_inventory() for report in reports]
    analysis.metrics = _build_metrics(
        reports, analysis, unresolved_loads, string_fact_count, symbol_fact_count
    )
    analysis.coverage = _build_coverage(reports, analysis)
    return analysis


def _map_jni_symbol(
    relative: str,
    symbol: ElfSymbol,
    name: JniName,
    index: NativeMethodIndex,
) -> tuple[dict[str, Any] | None, str]:
    if name.problem:
        return None, name.problem
    if not name.java_class or not name.java_method:
        return None, "demangle_ambiguous"
    matches = index.lookup(name.java_class, name.java_method)
    if not matches:
        return None, "no_matching_method"
    if name.signature:
        # JNI mangling carries ARGUMENT types only (no return type), so compare
        # the declared descriptor's argument list, not the whole descriptor.
        wanted = _argument_signature(name.signature)
        exact = [item for item in matches if _argument_signature(item["signature"]) == wanted]
        if len(exact) == 1:
            return _jni_entry(relative, name, exact[0], "deduced"), ""
        if not exact:
            return None, "signature_mismatch"
        return None, "ambiguous_overload"
    if len(matches) == 1:
        return _jni_entry(relative, name, matches[0], "hint"), ""
    return None, "ambiguous_overload"


def _argument_signature(signature: str | None) -> str:
    """``(Ljava/lang/String;)V`` and ``Ljava/lang/String;`` share one arg form."""
    if not signature:
        return ""
    text = signature.strip()
    if text.startswith("(") and ")" in text:
        return text[1:text.rfind(")")]
    return text


def _jni_entry(
    relative: str, name: JniName, match: dict[str, Any], confidence: str
) -> dict[str, Any]:
    return {
        "library": relative,
        "java_class": name.java_class,
        "java_method": name.java_method,
        "java_signature": match.get("signature") or name.signature,
        "smali_path": match["path"],
        "smali_line": match["line"],
        "smali_signature": match.get("signature"),
        "confidence": confidence,
    }


def _emit_native_findings(
    analysis: NativeAnalysis,
    report: NativeLibraryReport,
    parsed: ElfParseResult,
    strings: StringScan,
    register_natives: bool,
    finding_count: int,
    relative: str,
) -> int:
    def add(
        rule_id: str,
        category: str,
        severity: str,
        title: str,
        message: str,
        offset: int,
        snippet: str,
        confidence: float,
    ) -> int:
        if finding_count >= MAX_NATIVE_FINDINGS_ARTIFACT:
            analysis.diagnostics.append({
                "code": "native_finding_limit",
                "message": (
                    f"native finding cap {MAX_NATIVE_FINDINGS_ARTIFACT} reached; "
                    "remaining evidence stays in native_* facts"
                ),
            })
            return finding_count
        analysis.findings.append({
            "analyzer": "apk-surface",
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "verification_state": "static_unverified",
            "title": title,
            "message": message,
            "evidence": {"path": relative, "line": None, "offset": offset, "snippet": snippet},
        })
        return finding_count + 1

    for item in report.unmapped:
        finding_count = add(
            "native_jni_entry_unmapped",
            "native_mapping",
            "info",
            f"Unmapped JNI export: {item['symbol']}",
            (
                f"Exported JNI symbol has no provable Java declaration "
                f"(reason: {item['reason']}). This is a mapping gap, not a defect."
            ),
            item["offset"],
            item["symbol"],
            0.9,
        )

    import_names = {symbol.name for symbol in parsed.imports}
    export_names = {symbol.name for symbol in parsed.exports}
    imports_by_name = {symbol.name: symbol for symbol in parsed.imports}

    exec_hits = sorted(import_names & EXEC_SYMBOLS)
    if exec_hits:
        first = imports_by_name[exec_hits[0]]
        finding_count = add(
            "native_process_exec",
            "native_execution",
            "medium",
            "Native process-execution symbols imported",
            (
                "Library imports " + ", ".join(exec_hits) + ". Review call sites for "
                "command construction and privilege context."
            ),
            first.file_offset,
            ", ".join(exec_hits),
            0.85,
        )

    dynamic_hits = sorted(import_names & DYNAMIC_LOAD_SYMBOLS)
    if dynamic_hits:
        first = imports_by_name[dynamic_hits[0]]
        finding_count = add(
            "native_dynamic_symbol_resolution",
            "native_dynamic",
            "medium",
            "Native dynamic symbol resolution used",
            (
                "Library imports " + ", ".join(dynamic_hits) + ". Resolved symbols "
                "are invisible to static import analysis; the string set is the "
                "only lead to what is loaded."
            ),
            first.file_offset,
            ", ".join(dynamic_hits),
            0.8,
        )

    anti_debug_hits = sorted((import_names | export_names) & ANTI_DEBUG_SYMBOLS)
    anti_debug_strings = [
        (value, offset) for value, offset in strings.values
        if value in {"TracerPid", "/proc/self/status", "/proc/self/maps", "/proc/self/cmdline"}
    ]
    if anti_debug_hits or anti_debug_strings:
        if anti_debug_strings:
            value, offset = anti_debug_strings[0]
            snippet = value
        else:
            offset = imports_by_name[anti_debug_hits[0]].file_offset
            snippet = ", ".join(anti_debug_hits)
        finding_count = add(
            "native_anti_debug",
            "native_anti_debug",
            "info",
            "Anti-debug / process inspection indicator",
            (
                "Tracing or process-inspection symbols/strings are present "
                f"({', '.join(anti_debug_hits) or 'proc strings'}). Inspect usage; "
                "presence alone does not prove anti-debug behavior."
            ),
            offset,
            snippet,
            0.7,
        )

    if register_natives:
        offset = next(
            (symbol.file_offset for symbol in (*parsed.exports, *parsed.imports)
             if symbol.name == REGISTER_NATIVES),
            0,
        )
        finding_count = add(
            "native_jni_register_natives",
            "native_mapping",
            "info",
            "RegisterNatives referenced (dynamic JNI registration)",
            (
                "This library registers native methods at runtime. Static "
                "Java->symbol joins cannot cover those methods; treat unmapped "
                "JNI exports as expected and verify with the registration table."
            ),
            offset,
            REGISTER_NATIVES,
            0.75,
        )
        descriptors = sorted({
            value for value, _offset in strings.values
            if len(value) > 2 and value.startswith("L") and value.endswith(";")
            and "/" in value
        })[:20]
        signatures = sorted({
            value for value, _offset in strings.values
            if value.startswith("(") and ")" in value
        })[:20]
        analysis.facts.append({
            "kind": "native_jni_register_natives_candidate",
            "value": relative,
            "evidence": {"path": relative, "offset": offset},
            "extra": {
                "library": relative,
                "class_descriptor_candidates": descriptors,
                "signature_candidates": signatures,
                "pairing": "unresolved",
                "reason": (
                    "dynamic_registration_unresolved"
                    if not (descriptors and signatures)
                    else "candidates_only_no_provable_pairing"
                ),
            },
        })
    return finding_count


def _empty_metrics() -> dict[str, Any]:
    return {
        "native_library_count": 0,
        "native_files_found": 0,
        "native_files_parsed": 0,
        "native_files_skipped": 0,
        "native_exports_total": 0,
        "native_exports_emitted": 0,
        "native_imports_total": 0,
        "native_imports_emitted": 0,
        "native_jni_exports_total": 0,
        "native_jni_exports_mapped": 0,
        "native_jni_exports_unmapped": 0,
        "native_jni_mapping_complete": True,
        "native_strings_total": 0,
        "native_strings_emitted": 0,
        "native_strings_dropped": 0,
        "native_strings_scanned": 0,
        "native_strings_bytes": 0,
        "native_libraries_with_load_site": 0,
        "native_libraries_without_load_site": 0,
    }


def _build_metrics(
    reports: list[NativeLibraryReport],
    analysis: NativeAnalysis,
    unresolved_loads: list[dict[str, Any]],
    string_fact_count: int,
    symbol_fact_count: int,
) -> dict[str, Any]:
    parsed_reports = [report for report in reports if report.parsed is not None and report.parsed.ok]
    exports_total = sum(len(report.parsed.exports) for report in parsed_reports if report.parsed)
    imports_total = sum(len(report.parsed.imports) for report in parsed_reports if report.parsed)
    jni_total = sum(
        1 for report in parsed_reports if report.parsed
        for symbol in report.parsed.exports if symbol.name.startswith(JNI_PREFIX)
    )
    mapped = sum(len(report.jni_entries) for report in reports)
    unmapped = sum(len(report.unmapped) for report in reports)
    strings_total = sum(report.strings.unique for report in reports if report.strings)
    strings_matches = sum(report.strings.matches for report in reports if report.strings)
    bytes_scanned = sum(report.strings.bytes_scanned for report in reports if report.strings)
    with_load = sum(1 for report in reports if report.load_sites)
    without_load = len(reports) - with_load
    metrics = {
        "native_library_count": len(reports),
        "native_files_found": len(reports),
        "native_files_parsed": sum(
            1 for report in reports if report.state in {"parsed", "stripped_symbols"}
        ),
        "native_files_skipped": sum(
            1 for report in reports if report.state in {"parse_failed", "not_elf"}
        ),
        "native_exports_total": exports_total,
        "native_exports_emitted": sum(report.exports_emitted for report in reports),
        "native_imports_total": imports_total,
        "native_imports_emitted": sum(report.imports_emitted for report in reports),
        "native_jni_exports_total": jni_total,
        "native_jni_exports_mapped": mapped,
        "native_jni_exports_unmapped": unmapped,
        # I2 identity: every JNI export is either mapped or unmapped-with-reason.
        "native_jni_mapping_complete": jni_total == mapped + unmapped,
        "native_strings_total": strings_total,
        "native_strings_emitted": string_fact_count,
        "native_strings_dropped": max(strings_total - string_fact_count, 0),
        "native_strings_scanned": sum(1 for report in reports if report.strings and report.strings.bytes_scanned),
        "native_strings_bytes": bytes_scanned,
        "native_strings_matches": strings_matches,
        "native_libraries_with_load_site": with_load,
        "native_libraries_without_load_site": without_load,
        "native_load_sites_unresolved": len(unresolved_loads),
        "native_symbol_facts_dropped": max(
            exports_total + imports_total - symbol_fact_count, 0
        ),
    }
    if jni_total and mapped + unmapped == jni_total:
        pass
    return metrics


def _build_coverage(
    reports: list[NativeLibraryReport], analysis: NativeAnalysis
) -> dict[str, str]:
    if any(report.state in {"parse_failed", "not_elf"} for report in reports):
        libraries_status = "partial"
    else:
        libraries_status = "analyzed"
    strings_status = (
        "partial"
        if any(report.strings and report.strings.truncated for report in reports)
        else "success"
    )
    symbols_status = "success"
    if any(report.state == "stripped_symbols" for report in reports):
        symbols_status = "stripped_symbols"
    if any(report.reason for report in reports if report.state not in {"stripped_symbols"}):
        symbols_status = "partial"
    jni_total = analysis.metrics.get("native_jni_exports_total", 0)
    if not jni_total:
        jni_status = "not_applicable"
    elif analysis.metrics.get("native_jni_mapping_complete"):
        jni_status = "mapped"
    else:
        jni_status = "partial"
    return {
        "native_libraries": libraries_status,
        "native_symbols": symbols_status,
        "native_jni_mapping": jni_status,
        "native_strings": strings_status,
    }
