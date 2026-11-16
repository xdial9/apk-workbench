# SCANNER PLAN — surface analyzer to 360° (canonical track file)

Status: **P0 DONE, P1 DONE, P2 DONE (a/b/c), P3 NEXT.** Verified
2026-11-16, 321 tests green, tree clean, branch pushed.
This file is the resume point for the scanner track. Read it after
`ai-memory/INDEX.md` §STATE and before touching `analysis/`.

Owner rule (agreed with the user 2026-11-16): **after every phase, update this
file AND `/home/user/oc-handoff/99-briefing.md`, and commit.** No phase is
"done" until both are written and the tree is clean.

--------------------------------------------------------------------------------
## 0. WHY THIS TRACK EXISTS
--------------------------------------------------------------------------------
The 2026-11-16 line-by-line audit of the scanner (driver + all of
`analysis/surface/*` + `analysis/androguard_dex.py`) found it was **not**
360-ready, despite 271 green tests:

1. It did not visit the artifact. Only 20 text suffixes were read
   (`classify.py:21-25`); images, fonts, `.dat`, `.bin`, `.db`, `.arsc`,
   `META-INF/*`, and any `.dex` inside `assets/` were counted and dropped.
2. There was no code model: no class/method/field inventory, no annotations,
   no reflection sites, no resource-id model.
3. There was no link graph. `URL -> method -> caller -> entry point ->
   permission -> native -> secret` was implied in prose, never emitted as data.
4. Caps deleted data instead of sharding it.
5. Coverage values asserted work that never happened.

Everything below is the fix ladder. P0-P1 are done and verified.

--------------------------------------------------------------------------------
## 1. PHASE LADDER (one phase per prompt; do not reorder without the user)
--------------------------------------------------------------------------------

| Phase | Scope | Status | Commit |
|---|---|---|---|
| P0 | Truth in the data plane: per-file ledger, honest coverage, shard not drop | **DONE** | `a88eac2`, `131fd69` |
| P1 | Identity/trust: signing schemes, certificates, ABIs, uses-library | **DONE** | `50bb2d0`, `ec9419d` |
| P2a | Resource table: `resources.arsc` -> id/type/name/value -> `resources.jsonl` | **DONE** | `25e54b4` |
| P2b | Resource links: smali id cross-ref + decoded-XML file attribution | **DONE** | `133cb45` |
| P2c | FileProvider `file_paths.xml` roots + layout/view inventory | **DONE** | `4adb6a5` |
| P3 | Code model: class/method/field inventory, call graph v2, reflection sites | queued | — |
| P4 | Link graph: typed edges with two cites each + entry_points | queued | — |
| P5 | Detection breadth: 11 deduction templates, rule catalog 19 -> ~60 | queued | — |
| P6 | Containers: extract `.dex`/`.jar`/nested zips and analyse them | queued | — |
| P7 | Scale: single-pass streaming, checkpoint, shard by unit | queued | — |
| P8 | Handoff: `surface/` layout, bundle aggregation, workbook v2, prompts | queued | — |

### P0 — DONE (a88eac2 + 131fd69)
- `surface/ledger.py`: one JSONL record per tree entry in `files.jsonl`
  (path, status, reason, size, suffix, content_kind, analysed_by). Closed
  status set: `scanned_text`, `analysed_native`, `skipped_container`,
  `skipped_binary`, `skipped_unsupported`, `skipped_symlink`, `undecodable`.
  Closed reason set; each reason bound to exactly one status. Summary lands in
  `inventory.file_ledger` (total/checked/not_checked/by_status/by_reason +
  vocabularies).
- `classify.py`: symlinks and unreadable entries are now **named**
  (`tree.symlinks`, `tree.unreadable`), not just counted.
- `classify.py`: magic table extended (png, jpeg, gif, riff, pdf, font,
  arsc) so a skipped file can say which binary it is.
- `coverage.resource_inventory` no longer says `success` just because `res/`
  exists: `counted_not_parsed` / `not_found`.
- `surface/shards.py` + `shards-index.json`: native symbol (20k), string
  (60k), finding (200) and per-library string (50k) overflow now streams to
  `shards/<prefix>-part-NNN.jsonl` (5k/part, 0600) with a verifiable index
  (file, records, first/last key, sha256, totals). Metrics split
  `*_emitted` / `*_sharded` / `*_dropped`; `dropped` is 0 when a shard sink
  exists. Coverage gains the value `sharded`.
- `surface/patterns.py`: one hardened `DOMAIN_RE` (possessive quantifiers),
  shared by `sweep` and `androguard_dex`; the two unhardened copies deleted.
- `analyze_apk_surface(..., output_dir=)`: the artifact folder receives
  `files.jsonl` and `shards/`. (Was `ledger_dir` in a88eac2.)

### P1 — DONE (50bb2d0 + ec9419d)
- `surface/identity.py`, stdlib only (no `cryptography`, no `apksigner`):
  - bounds-checked DER reader + X.509 parse (subject, issuer, serial,
    validity, key/signature algorithm, self-issued);
  - APK Signing Block v2 / v3 / v3.1 (EOCD -> block, 8 MiB cap) -> every
    signer certificate + v3 min/max SDK;
  - v1 PKCS#7 certificate from `META-INF/*.RSA|DSA|EC` + per-file SHA-256;
  - ABIs and zip totals from the central directory.
- Certificates are cited by the **SHA-256 of their DER bytes**, never a name.
- New facts: `apk_signing_scheme`, `apk_signing_certificate`, `apk_abi`,
  `uses_library`, `uses_native_library`.
- New findings: `apk_unsigned` (high), `apk_signed_v1_only` (medium),
  `apk_debug_certificate` (high). **No expiry finding** — it would flip with
  the clock and break determinism; dates are facts.
- New coverage key `apk_identity`: `success | partial | failed | not_found`.
- New citation scheme `apk:<file>` (added to `NON_PATH_CITE_PREFIXES`) so an
  APK-level fact is never rewritten as `apktool/apk:...`.
- Driver now verifies the APK SHA-256 **before** the scan, not after.
- `ec9419d`: `insecure_http` no longer fires on
  `xmlns:android="http://schemas.android.com/apk/res/android"`. It fired on
  every manifest ever scanned.

### P2a — DONE (resource table)
- `surface/resources.py`: stdlib ResTable reader. Chunk header walk, UTF-8 and
  UTF-16 string pools, package/typeSpec/type chunks, sparse and offset16
  entry tables, `Res_value` decoding (string, reference, attribute, int dec /
  hex, boolean, float, dimension, fraction). Complex (bag) entries are
  recorded as `value_type: "complex"`; compact entries (Android 14 flag) are
  counted with a diagnostic instead of being misparsed.
- Records stream to `resources.jsonl` (atomic: temp + fsync + replace, 0600)
  while parsing, so a 200k-record table never exists twice in memory.
  Record shape: `id, package, type, name, config, value, value_type,
  reference` — same keys every run.
- Summary in `inventory.resource_model` (status, entry_count, type_counts,
  packages, string_pool_size, resources_jsonl); full diagnostics go to the
  artifact diagnostics.
- New coverage key `resource_model` (success/partial/not_found/failed).
  `resource_inventory` now says `parsed` when the table parsed, so the old
  `counted_not_parsed` is no longer a lie.
- No records are emitted without an APK: `resource_model = not_found`.

### P2b — DONE (resource links)
- `sweep.py` collects resource-id literals from smali
  (`0x<package><entry>`, package byte filtered against the packages actually
  present in the table, so an arbitrary 32-bit constant is not mistaken for
  an id).
- resolution against the parsed table produces:
  * `resource_id_used` — value `0x7f010000`, extra `type`, `name`,
    `resource_value`, `config`, `file`, evidence = every `path:line` that
    references it (count == occurrences);
  * `resource_id_unresolved` — reason `not_in_resource_table`.
- new coverage key `resource_links`: `success` (all resolved) /
  `partial` (some unresolved) / `not_applicable` (no id literals).
- new metrics: `resource_id_references`, `resource_ids_resolved`,
  `resource_ids_unresolved`.
- `resources.py` gained `index_value_files()`: scans decoded
  `res/values*/**/*.xml` and maps `(type, name) -> file`, plain `res/values/`
  winning over qualified config dirs. Every `resources.jsonl` record now
  carries `file` (null when the decoded tree does not declare it).
- **FactStore guard**: `extra` may no longer overwrite `kind`, `value`,
  `fingerprint`, `count` or `evidence`. Passing `extra={"value": ...}`
  silently replaced the fact's own value (it happened twice); it now raises.

### P2c — DONE (provider + layout surface)
- `surface/xml_assets.py`:
  * `collect_file_providers()` joins every `<provider>` carrying a
    `FILE_PROVIDER_PATHS` meta-data to its decoded `res/xml/*.xml` and emits
    `file_provider_root` facts (authority, provider, root_type, name, path,
    exported, meta_data). A reference with no decoded file is a diagnostic
    (`file_provider_paths_missing`), never a guess.
  * new finding `file_provider_exported` (high) when an exported provider
    actually serves roots.
  * `collect_layouts()` emits one `layout` fact per `res/layout*/*.xml`
    (view_count, views, ids, custom_views) and one `custom_view` fact per
    qualified/unknown view class, with every layout that uses it as evidence.
- new coverage keys `file_provider_paths` and `layout_inventory`
  (success/partial/failed/not_found); metrics `file_provider_root_count`,
  `layout_count`, `custom_view_count`.
- **P2 is complete.** Next: P3 code model.

### P3 — Code model
Class/method/field inventory with DEX index + smali path (name, access,
superclass, interfaces, signature, annotations); call graph v2 (add
caller_class/callee_class + dex file; keep external refs **with and without**
callers — today `androguard_dex.py:180-183` drops the callerless ones);
string -> class index; reflection sites (`Class.forName`, `Method.invoke`,
`getDeclaredMethod`); one-hop dynamic-load target resolution.
Exit: class count == DEX class count; every method has a cite.

### P4 — Link graph
One `links.jsonl` of typed edges, two cites each: `component->class`,
`class->method`, `method->method`, `method->endpoint`, `endpoint->permission`,
`method->native`, `native->secret`, `asset->reader`. Plus
`entry_points.jsonl` (exported component, deep link, receiver, provider URI,
service, Application class).
Exit: the ten questions below are answerable by querying `links.jsonl`.

### P5 — Detection breadth
Implement the 11 templates from `appdev.txt` §12 (5 exist); grow
`CODE_RULES` from 19 to a catalog (reflection, pinning, keystore, SQL string
building, path traversal, intent redirection, exported provider, task
hijacking, overlay, clipboard, accessibility, root/emulator checks, dynamic
dex, native exec); secret/entropy classification for DEX strings and binary
blobs. Exit: positive + negative fixture per rule; `docs/rules.md`.

### P6 — Containers and packed code
Extract **all** code-bearing members (`.dex`, `.jar`, `.apk`, nested zips),
streamed and bounded, feed them to the DEX analyzer with `container!member`
citations. Today only `.so` members are extracted (`native.py:57`), so a
packed app's real dex is invisible to both the sweep and Androguard.

### P7 — Scale
Single-pass streaming writes, bounded memory, per-file checkpoint
(`surface/checkpoint.py` exists and is unused), shard by natural unit.
Exit: the 112k-file case completes inside the RAM budget and resumes after a
kill. Measured baseline: 57,944/112,254 files at ~39 files/s, killed at
1,481 s with nothing persisted (`todo.md` history).

### P8 — Handoff
`surface/` layout, bundle aggregation across components, `handoff.json`,
freeze + `hashes.sha256`, `verify-workspace`, workbook v2 with executable
trace recipes, prompts 0..6 aligned with what exists.

--------------------------------------------------------------------------------
## 2. DEFINITION OF DONE (the scanner is "360-ready" when...)
--------------------------------------------------------------------------------
An AI can answer these **from the bundle alone, with a citation**:

1. Who signed it, with what certificate SHA-256, under which scheme? — **DONE (P1)**
2. Package, version, SDK range, ABI set, split set, install size? — partial (ABIs/SDKs yes; split set is bundle-level, P8)
3. File count, how many analysed, and for each skipped file: why? — **DONE (P0)**
4. What classes exist, how many methods each, where declared? — P3
5. Which component is exported, which class implements it, what can invoke it? — P4
6. Which endpoint is called by which method, from which entry point? — P4
7. Which permission gates that path, is it requested? — P4
8. Which native library implements which declared method, who calls it? — **DONE (N1-N13)**
9. Which secret exists, in which file/offset/method, who uses it? — partial (native only)
10. What could the scanner not see, and what is the evidence? — partial (coverage + ledger; packed/encrypted evidence is P6)

--------------------------------------------------------------------------------
## 3. AUDIT DEFECT LEDGER (D1-D18) — keep this current
--------------------------------------------------------------------------------
| # | Defect | Status |
|---|---|---|
| D1 | `resource_inventory=success` without parsing | **FIXED** P0 |
| D2 | `packed_indicator` deduction has no evidence | open |
| D3 | `obfuscation_metric` deduction has no evidence | open |
| D4 | external methods without callers dropped, metric hides it | open (P3) |
| D5 | DEX strings deduped by value, DEX-of-origin lost | open (P3) |
| D6 | stripped-section ELF yields no symbols despite `PT_DYNAMIC` | open (P3/native) |
| D7 | load-site map keyed on basename only | open |
| D8 | `text_file_limit` / `finding_limit` referenced, never emitted | **FIXED** P0 |
| D9 | one finding per endpoint/route (inventory noise) | open (P5) |
| D10 | `SENSITIVE_PERMISSIONS` dead duplicate in `apk_surface.py:53` | open |
| D11 | unhardened `DOMAIN_RE` (ReDoS) x2 | **FIXED** P0c |
| D12 | `manifest_v2.py` severity if/else identical | open |
| D13 | run marker writes `eligible=0` before computing it | open (Unit 1) |
| D14 | `finalize_result` runs twice per artifact | open |
| D15 | whole-file `read_text`, no size guard, no streaming | open (P7) |
| D16 | no per-file status ledger | **FIXED** P0 |
| D17 | facts/ledger written at artifact root, not `surface/` | open (P8) |
| D18 | only 3 driver-level tests | improved (301 total) |

Fixed outside the ledger:
- `insecure_http` false positive on the Android XML namespace (`ec9419d`).
- `FactStore.add(extra=...)` could overwrite the fact's own `kind` / `value` /
  `fingerprint` / `count` / `evidence`. It corrupted facts twice (endpoint
  kind, resource value) before the guard in `facts.py` made it raise (P2b).

--------------------------------------------------------------------------------
## 4. DECISIONS TAKEN (do not re-litigate without the user)
--------------------------------------------------------------------------------
- New bundle files are additive and stable: `files.jsonl`, `shards-index.json`,
  `resources.jsonl` (P2), `links.jsonl` + `entry_points.jsonl` (P4).
  `static-analysis.json` stays the summary plane.
- Citations: `path:line` for text, `path@0xOFFSET` for bytes, `apk:<file>` for
  APK-level facts, and the existing pseudo-schemes (`endpoint:`, `permission:`,
  `sdk_root:`, `coverage:`, `route:`, `fact:`).
- No time-dependent verdicts (no "certificate expired" finding).
- Caps never delete: shard + count + coverage `sharded`.
- ARSC is parsed by us (stdlib), decoded XML used as cross-check.
- Control-flow / decompiled pseudo-code is NOT in scope before P4 (weeks, not
  days).

--------------------------------------------------------------------------------
## 5. RESUME PROTOCOL (run these first)
--------------------------------------------------------------------------------
```bash
cd /home/user/APK-Workbench
git status -sb && git log --oneline -8
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python -m ruff check . --output-format=concise   # baseline: 23 errors
```
Then read, in order: this file, `ai-memory/INDEX.md` §STATE,
`/home/user/oc-handoff/99-briefing.md`, `ai-memory/todo.md` (Unit 1, still
queued, different track).

Rules that already cost us once: never edit from memory, always re-read the
file; never claim a phase done without a test run pasted in full; update this
file and the briefing **before** the final commit of a phase.

--------------------------------------------------------------------------------
## 6. TEST MAP (scanner)
--------------------------------------------------------------------------------
| Area | File | Tests |
|---|---|---|
| driver end-to-end | `tests/test_apk_surface.py` | 5 |
| ledger | `tests/test_surface_ledger.py` | 8 |
| shards | `tests/test_surface_shards.py` | 6 |
| identity | `tests/test_identity.py` | 11 |
| resources (table + links) | `tests/test_resources.py` | 12 |
| provider + layout | `tests/test_xml_assets.py` | 7 |
| sweep | `tests/test_surface_sweep.py` | 16 |
| classify | `tests/test_surface_classify.py` | 7 |
| facts / handoff / workbook | `tests/test_surface_facts.py` (9), `test_surface_handoff.py` (10), `test_surface_serialize.py` (4) | 23 |
| native | `tests/test_native_*.py` (4 files) | 51 |
| DEX | `tests/test_androguard_dex.py` | 4 |

Scanner-related tests: 150 of the 321 collected. Hermetic fixture builders:
`tests/elf_fixtures.py`, `tests/identity_fixtures.py`, `tests/arsc_fixtures.py`.

--------------------------------------------------------------------------------
## 7. COMMIT LOG (scanner track, oldest first)
--------------------------------------------------------------------------------
| Commit | What |
|---|---|
| `a88eac2` | P0: per-file ledger (`files.jsonl`), named symlinks/unreadable, extended magic table, honest `resource_inventory`, dead diagnostics removed |
| `131fd69` | P0c: shard overflow (`shards/*.jsonl` + `shards-index.json`), metrics emitted/sharded/dropped, one hardened `DOMAIN_RE` |
| `50bb2d0` | P1: APK identity (signing block v2/v3/v3.1, v1 PKCS#7, ABIs) + `apk:` citations |
| `ec9419d` | fix: `insecure_http` no longer fires on the Android XML namespace |
| `25e54b4` | P2a: `resources.arsc` -> `resources.jsonl` |
| `133cb45` | P2b: smali resource-id resolution + definition files + FactStore guard |
| `4adb6a5` | P2c: FileProvider roots + layout/view inventory (P2 complete) |

Memory-only commits interleaved: `a7aa2af`, `eadf73d`, `45bec3e`, `cb52d53`.
Push state: `origin/feat/native-elf-reader` tracks HEAD. `main` is still
`ca2858c` (pre-scanner) — promoting it is the user's call.
