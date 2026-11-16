# NATIVE (JNI) SCANNER — DISCOVERY + MAPPING TO 100% (plan v1)

Status: N1-N12 IMPLEMENTED on branch feat/native-elf-reader (commits below).
N13-lite (NEEDED graph reasons) done; N13 asset-embedded .so still deferred.
Canonical home for the native track (appdev.txt §4 keeps the domain knowledge;
this file owns the plan and the step state).

Baseline: main @ 9d4fea4 (217 tests) -> branch feat/native-elf-reader
(262 tests green). Analyzer id stays apk-surface.

--------------------------------------------------------------------------------
WHY THIS FILE EXISTS
--------------------------------------------------------------------------------
AGENTS.md crown jewel 5: "Every native export must carry its JNI mapping to the
Java method that calls it, or be marked unmapped_jni with a reason. Never leave
it unmapped with no reason." Today the surface analyzer does strings-only
(`apk_surface.py:432-465`), so crown jewel 5 is at ~15%: files are listed, bytes
are scanned, nothing is mapped. This plan closes that gap in small steps.

--------------------------------------------------------------------------------
WHAT 100% MEANS (measurable; no adjectives)
--------------------------------------------------------------------------------
Per artifact, all five identities must hold and be provable from the bundle:

 I1 FILE   native_files_found == native_files_parsed + native_files_skipped(with reason)
 I2 SYMBOL per lib: exports_total == exports_mapped_to_java + exports_unmapped(with reason)
 I3 STRING native_strings_total == native_strings_emitted (+ sharded count if capped)
 I4 LOAD   so_files_found == so_files_with_load_site + so_files_no_load_site(with reason)
 I5 CITE   every native fact/finding has a location (path + byte offset), never line numbers

Every JNI fact carries: lib path, symbol, demangled class/method/signature,
resolving smali file:line, and confidence. Every unmapped export carries a
reason from a closed set. "100%" still does not claim runtime truth (JNI can be
registered dynamically); unprovable links are labelled, never invented.

--------------------------------------------------------------------------------
CURRENT STATE — line-by-line review (evidence, 2026-11-16)
--------------------------------------------------------------------------------
- apk_surface.py:235  _NATIVE_STRING_RE = rb"[ -~]{4,}"  -> ASCII only, no
  UTF-16LE. JNI signatures (Ljava/lang/String;)V in UTF-16 are INVISIBLE.
- apk_surface.py:237-257 _extract_native_strings: reads max_bytes+1 into RAM
  (50 MB), and on truncation does `pass` although the docstring says the caller
  records a diagnostic. The caller (439-450) never checks. SILENT CAP —
  violates the completeness law; a 90 MB .so loses ~40 MB of strings unseen.
- apk_surface.py:297-300 native_libraries = suffix in {".so",".a"} — no ELF
  magic check (a zip named .so is "scanned" as text and reports nothing).
- apk_surface.py:439-465 sweeps native "text" through the SMALI rules
  (SMALI_INVOKE_RE, Retrofit annotation, dependency markers). Almost none can
  fire on C strings; no native-specific rule exists. No findings are emitted
  for native at all.
- apk_surface.py:450 native secret hints: substring match, value truncated to
  500 chars, path only (no offset).
- apk_surface.py:577-582 facts: native_library (path only), native_secret_hint.
  No export/import/JNI/load facts.
- apk_surface.py:478 and 615-616 set coverage["native_libraries"] twice; the
  478 write ("inventory_only") is dead and misleading.
- handoff.py:72-88 _locations renders only `path:line` or `path`; a byte offset
  cannot be expressed, so native cites will be location-less unless extended.
- classify.py:28-40 sniffs ELF magic but uses it only for counters/archives.
- No dependency on pyelftools/lief/capstone (verified absent) -> stay stdlib.
- tests: only tests/test_apk_surface.py:49-55 asserts the inventory path. Zero
  content tests for native.

--------------------------------------------------------------------------------
STATE (verified 2026-11-16, branch feat/native-elf-reader)
--------------------------------------------------------------------------------
Modules:
- analysis/surface/native_elf.py  — header, program headers, sections, .dynamic,
  build-id, .dynsym/.symtab split. Every symbol carries file_offset (byte cite).
- analysis/surface/native.py      — JNI demangle+join, load-site resolver,
  strings v2, findings, identities/metrics/coverage.
- analysis/apk_surface.py         — wires both, keeps native_strings_* keys.
- surface/handoff.py + workbook.py — path@0xOFFSET cites + address_space.
- reporting/final_run.py          — native counters in the static stage.

Exit evidence (tests): tests/test_native_elf.py (11), tests/test_native_analysis.py
(23), tests/test_native_adversarial.py (8), handoff native cite tests (2),
final-run native counter test. Full suite 262 passed.

MEASURED (N12, this box, real host libraries; peak RSS ~51 MB for the pass):
  libc.so.6        2.0 MB  exports 3141   parse 0.07 s  strings 0.29 s  unique 10 848
  libgtkmm 5.3 MB          exports 18293  parse 0.55 s  strings 0.69 s  unique 28 551
  libLLVM 129.7 MB         exports 51988  parse 1.21 s  strings 17.6 s  unique 50 000 (cap hit -> truncated)
Interpretation: parsing is header/section-bounded (~1 s even at 130 MB); string
scan is the linear cost (~0.13 s/MB). Android .so files are normally 1-10 MB,
so a full APK worth of native code is a few seconds. The 130 MB outlier hits the
per-library string cap, which is recorded (diagnostic + coverage partial).

Identities as implemented:
  I1 metrics.native_files_found == native_files_parsed + native_files_skipped
  I2 metrics.native_jni_exports_total == mapped + unmapped  (native_jni_mapping_complete)
  I3 native_strings_total == native_strings_emitted + native_strings_dropped
  I4 with_load_site + without_load_site(s each with reason fact)
  I5 every native fact evidence = {path, offset}; address_space=byte in handoff
Caps (all counted, never silent): 50k strings/lib, 60k string facts/artifact,
20k symbol facts/artifact, 200 native findings/artifact.

--------------------------------------------------------------------------------
STEPS (one phase each; stop + report after each)
--------------------------------------------------------------------------------
N1 [x] Pure-stdlib ELF reader skeleton — NEW analysis/surface/native_elf.py
    Scope: header (EI_CLASS/EI_DATA/e_type/e_machine), section header table walk,
    bounds-checked little/big-endian reads, never reads the whole file.
    API: parse_elf_header(path) -> ElfInfo | None plus a reason string.
    Exit: 5 tests (ELF64 LE, ELF32, big-endian header, truncation, garbage) and
    no behavior change to the artifact output. Why small: standalone module.

N2 [x] Sections -> dynamic facts
    Scope: .dynamic (SONAME, NEEDED, FLAGS, RUNPATH), .note.gnu.build-id,
    section names/sizes. Emit per-lib fact kind "native_elf" with evidence
    {path, offset} and the parsed fields.
    Exit: fixture asserts SONAME/NEEDED/FLAGS; malformed lib -> diagnostic
    "native_elf_parse_failed", never silent.

N3 [x] Symbol tables: exports + imports
    Scope: .dynsym (+ .symtab when present) with its .dynstr; keep only
    DEFINED GLOBAL/WEAK (export) and UNDEF (import); funcs vs objects.
    Emit "native_export" / "native_import" facts, value + st_value offset.
    Exit: counts identity I2 scaffold test (totals only, no mapping yet).

N4 [x] Native evidence addressing (cite syntax)
    Scope: handoff._locations + workbook accept a byte offset and render
    "path@0x<hex>"; JSONL/location_map carry "kind":"native" so the AI knows the
    address space. Existing smali/content cites unchanged (byte-identical).
    Exit: handoff test proves old output is unchanged for line cites, and that a
    native cite round-trips with has_location=true.

N5 [x] JNI export demangling + Java join
    Scope: "Java_<class>_<method>__<sig>" -> com.x.Y#m(Ljava/lang/String;)V
    (_1 _2 _3 _00024, arrays, overloaded __ separators). Build an index of
    declared `native` methods from smali once, join, emit "jni_entry"
    (lib, symbol, class, method, signature, smali file:line) or
    "unmapped_jni" with reason in {no_matching_method, native_method_missing,
    not_jni_symbol, stripped_symbols}.
    Exit: I2 holds on a 3-export fixture (2 mapped, 1 with reason).

N6 [x] RegisterNatives (dynamic registration) candidates
    Scope: detect JNI_OnLoad/RegisterNatives usage; pair class descriptor +
    JNI signature strings found in the same lib. Emit
    "jni_register_natives_candidate" (confidence hint) or "unmapped_jni" with
    reason "dynamic_registration_unresolved". Never guess a pairing.
    Exit: fixture with matching strings yields one hint fact; absent strings
    yield no fact (no invention).

N7 [x] Library load-site resolver (the caller half)
    Scope: smali scan for System.loadLibrary/System.load + const-string; map
    lib<name>.so to the smali file:line. Emit "native_library_load"; mark libs
    with no load site as "no_load_site_found" with reason
    (dependency_of_other_lib | unreferenced | obfuscated_path).
    Exit: I4 identity test on a fixture with 2 libs (1 loaded, 1 not).

N8 [x] Strings v2 — complete, streamed, honest caps
    Scope: chunked scan (windows with overlap), ASCII + UTF-16LE, dedupe by
    value keeping first offset, per-file cap becomes "native_string_limit"
    diagnostic + coverage partial + exact bytes-scanned counters.
    Emit "native_string" facts (value, offset) and derive secret hints from the
    deduped set (drop the 500-char truncation).
    Exit: I3 test (count equality), UTF-16 fixture, cap fixture proves
    diagnostic + partial (no silent loss).

N9 [x] Native findings (closed, evidence-only rule set)
    Scope: native_jni_entry_unmapped, native_dynamic_symbol_resolution,
    native_process_exec, native_anti_debug, native_jni_register_natives.
    Each fires only from parsed evidence and carries a byte-offset cite.
    Exit: one test per rule + a clean-lib fixture emitting zero findings.

N10 [x] Coverage + metrics + honest status
    Scope: per-lib state {elf_parsed, stripped_symbols, parse_failed,
    strings_truncated}; artifact-level I1..I4 counters; make status "partial"
    when any identity has a skipped element. Delete the dead line at
    apk_surface.py:478.
    Exit: 3-lib fixture (good/stripped/garbage) proves every lib is accounted.

N11 [x] Handoff + report wiring
    Scope: native counts into metrics, facts.jsonl/location_map (automatic),
    workbook leads for partial native coverage, final-run report counters.
    Exit: report test asserts native totals; handoff test asserts every native
    fact has a location.

N12 [x] Adversarial + performance gate
    Scope: ELF that is a zip, symlink, sparse 200 MB file, zero-export lib,
    symbol table with bad offsets; measure wall time + peak RSS on a real lib.
    Exit: suite green, timing/RSS recorded in this file (VERIFY numbers in).

N13 [~] (DEFERRED) NEEDED dependency graph across sibling libs; asset-embedded
    .so (Flutter/RN packers). Only after N1-N12 are green.

--------------------------------------------------------------------------------
DECISIONS / CONSTRAINTS (append-only)
--------------------------------------------------------------------------------
- 2026-11-16: stdlib-only ELF parsing. pyelftools/lief/capstone are NOT
  installed; adding a dependency is not required and not approved.
- 2026-11-16: native cites use path@0xOFFSET; native has no line numbers and
  inventing one is forbidden.
- 2026-11-16: keep inventory key native_libraries and existing coverage key
  names stable (appdev.txt §15 consumer contract); new keys additive only.
- 2026-11-16: do NOT route native strings through smali regex rules; native
  gets its own rule set (N9) to avoid invisible false positives.
- 2026-11-16: unmapped reasons are a closed set; a free-text reason is a bug.
  Implemented set (native.py UNMAPPED_REASONS): no_matching_method,
  not_jni_symbol, demangle_ambiguous, ambiguous_overload, signature_mismatch,
  stripped_symbols, dynamic_registration_unresolved, unreferenced,
  dependency_of_other_lib, not_elf_archive, obfuscated_path, no_load_site.
- 2026-11-16: symbol facts cite the .dynsym/.symtab RECORD offset (a true file
  offset) and carry st_value as `address`. st_value is a virtual address, so
  using it as a byte citation would be a lie.
- 2026-11-16: JNI mangling carries ARGUMENT types only (no return type), so the
  Java join compares argument signatures: `_argument_signature()` strips the
  descriptor down to the part between '(' and ')'.
- 2026-11-16: a `const-string` -> `System.load` pair is resolved with per-file
  register tracking (last const-string per register), evidence = invoke line.
- 2026-11-16: strings translate non-printables to NUL once per window and run a
  trivial regex (measured ~20% faster than a char-class regex over binary).
- 2026-11-16: native strings are swept as newline-joined text to reuse the
  endpoint/domain rules, then evidence is retargeted from synthetic line
  numbers to real byte offsets (_retarget_native_evidence). An endpoint found
  inside a string cites the START of the containing string: a substring's own
  offset would require a second search and adds no traceability.
- 2026-11-16: a non-ELF file named `.so` flips status to partial (coverage law),
  recorded as native_not_elf; it is never reported as "no symbols".

--------------------------------------------------------------------------------
RISKS / TRIPWIRES
--------------------------------------------------------------------------------
- Whole-file reads blow RAM on 3.8 GB box (D-8/D-4): always seek+read windows.
- Demangling is where guessing creeps in: every branch must be fixture-tested;
  unknown shapes become unmapped_jni, not best-effort names.
- Symbol tables can be huge: stream, sort, and cap by COUNT with a diagnostic,
  never silently.
- Stripped libs (no .dynsym) are normal and must read as stripped_symbols with
  a reason, not as "no exports" (empty-means-empty law).
- Do not let N5/N6 regress performance: the smali native-method index is built
  once per artifact, reused.
