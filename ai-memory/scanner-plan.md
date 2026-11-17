# SCANNER PLAN — surface analyzer to 360° (canonical track file)

Current state (verified 2026-11-17): **P0-P7 DONE; M0-M3 DONE**. M3 used real
Simple Calculator v85 evidence from run
`b8e85b99-a5f9-496d-b3a4-e15cb1deca73`: all 4 APK components were verified;
existing decoded and TruffleHog results were reused, then secret links and
trace chains were refreshed. Per-artifact `status.json` files now cover
download, verification, decompile, surface, and TruffleHog; run-level files
cover discover, download, verification, decompile, surface, TruffleHog,
report, reconciliation, freeze, and pipeline. A separate writable copy at
`/home/dial9/APK-Workbench/workspace-m3-postfix-real` produced the post-fix
report, froze all 4 bundles, and passed `verify-workspace` with zero
mismatches, missing files, or extras. The fixed cross-APK JNI matcher mapped
7 exports and left 0 unmapped; report and inventory agree. The three
non-base splits have no DEX payload; Androguard correctly returns
`not_applicable`, but the surface driver incorrectly marked any non-success
DEX result as a partial analysis. The driver now preserves the not-applicable
coverage and does not downgrade surface status. Cached successful reuse also
no longer makes the run status partial. All four surface results now report
success; DEX coverage is `success` for base and `not_applicable` for the
three splits. Reconciliation accounts for 4/4 as complete. The original
frozen bundles were not modified. The report is 758 MB JSON / 1.13 GB HTML
and remains a scale constraint. No fresh download, decompile, or TruffleHog
rescan was performed. P8 remains PARTIAL:
handoff/freeze mechanics exist, but model dry-run, output-contract enforcement,
and volume hierarchy are not validated. Full suite: **386 passed**. Current
open work is tracked in
[PRODUCT-RESCUE-BOARD.md](../docs/engineering/PRODUCT-RESCUE-BOARD.md).
The older 2026-11-16 status snapshots below are retained as history, not as the
current state.
This file is the resume point for the scanner track. Read it after
`ai-memory/INDEX.md` §STATE and before touching `analysis/`.

Owner rule: after every phase, update this file, `ai-memory/INDEX.md` §STATE,
and the repository-local `oc-handoff/99-briefing.md`, then commit the phase.
Do not rely on the unavailable `/home/user/oc-handoff/99-briefing.md` path.

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
| P3 | Code model: class/method/field inventory, call graph v2, reflection sites | **DONE** | `3de13fe` |
| P4 | Link graph: typed edges with two cites each + entry_points | **DONE** | `2c3d535` |
| P5 | Detection breadth: 29 evidence-backed rules, endpoint/route rollups | **DONE** | implementation + fixtures |
| P6 | Containers: bounded embedded `.dex`/`.jar`/`.apk` analysis | **DONE** | `a6c6826`, `c1854ea` |
| P7 | Scale: streaming, checkpoint, shard by unit | **DONE** | `68fd6d6` |
| P8 | Handoff: layout, bundle freeze, verification, workbook/prompts | **PARTIAL** | `72f2d7d`; model dry-run pending |

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

### P3 — DONE (`3de13fe`, verified 329 tests green)
Scope actually delivered (the prompt's list, not the whole plan line — no
`caller_class`/`callee_class` on edges, they are derivable from `full_name`;
noted as open below):
- `androguard_dex.py` new section after the internal_call_graph loop:
  * `class_model`: one entry per internal class — `dex_index, class_name,
    access_flags (string), superclass, interfaces, source_file, method_count,
    field_count, annotations`. `source_file` comes from
    `ClassDefItem.get_source_file_idx()` + `CM.get_string()`, `NO_INDEX`
    (0xFFFFFFFF) -> null. Class annotations via `get_annotations()`.
  * `method_model`: one entry per internal method — `class_name, method_name,
    full_name, access_flags, descriptor, annotations`. Method annotations come
    from the class `AnnotationsDirectoryItem` (method_idx -> type list), since
    EncodedMethod carries none. Join key to the call graph is `full_name`.
  * `string_class_index`: string value -> sorted list of referencing class
    names, built inside the existing `dx.get_strings()` loop (before the
    endpoint-candidate filter, so class-name literals are indexed). Values no
    class references are absent (documented in `limitations`), not dropped.
  * `reflection_sites`: one entry per hit on `Class->forName`,
    `Class->getMethod|getDeclaredMethod|getField|getDeclaredField`,
    `Method->invoke` — `caller, caller_class, api, offset,
    argument_resolved, resolved_target, resolution_kind, unresolved_reason`.
    One-hop resolution = nearest preceding string constant in the same method,
    ordered by xref offset. `Method->invoke` never resolves (its args are
    objects) -> `unresolved_reason=no_literal_argument`. Sorted for
    determinism.
  * `dex_class` (DEX index in `dx.vms`) on every `internal_call_graph` entry
    (edge origin = caller) and every `external_method_references` entry; also
    on every `call_sites` element, which is the only exact per-edge fact when
    one Analysis spans several DEX files. External methods have no owning DEX,
    so the entry-level value is set only when all call sites share one DEX.
  * metrics: `class_model_count`, `method_model_count`,
    `string_class_index_entries`, `reflection_site_count`,
    `external_methods_without_callers`. New coverage key `code_model`
    (`success | partial | not_applicable | failed | timed_out`).
  * every error/empty payload now carries the four new keys + a `coverage`
    entry, so the schema is stable across success/timeout/failure.
- `tests/test_androguard_dex.py`: 4 -> 12 tests. New real-APK fixture
  `tests/fixtures/dexfixture/dexfixture.apk` (apktool-built from the committed
  smali sources next to it: 3 classes, annotations, literal + parameter
  `Class.forName`, `getMethod`/`getDeclaredMethod`/`Method.invoke`). The
  monkeypatched stack became a reusable `install_fake_androguard()` helper
  that mirrors the introspected 4.1.4 surface.
- VERIFIED against the real library (not guessed): androguard 4.1.4
  `ClassAnalysis.get_vm_class()`, `get_methods()` (dict_values),
  `get_nb_methods()`, `get_fields()`, `MethodAnalysis.get_access_flags_string
  ()`, `get_method().get_method_idx()`, `get_vm()`, `ClassDefItem
  .get_source_file_idx()/get_interfaces()/get_annotations()/
  annotations_directory_item`, `ClassDefItem.CM.vm` as the DEX link (not
  `CD.CM is DEX` — that identity is false).
- Exit criteria: `len(class_model) == metrics.classes` and every
  `method_model`/`internal_call_graph` entry resolves to a `class_model`
  entry, both asserted on the real fixture.
- Observed, NOT fixed (new defect D19): list order in
  `internal_call_graph`, `external_references[].call_sites` and
  `dex_api_strings[].references` still comes from Python set iteration, so two
  runs are byte-different (content identical). Pre-existing at HEAD, proven by
  running the pre-P3 file 3x. The new P3 keys are deterministic.
- Not done here (P3 plan line, outside this prompt): `caller_class`/
  `callee_class` keys on edges; field-level model (only `field_count`).
- `.venv` did not exist in this checkout; recreated from `pyproject.toml`
  (androguard==4.1.4) before any work. `ai-memory/*` files were already
  modified (0-line/mode-only diffs) before this phase started.

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

### P4 — DONE (`2c3d535`, verified 341 tests green)

**What was built** — `src/apkworkbench/analysis/surface/links.py`:
- `build_link_graph(surface_result, dex_result, *, trufflehog_findings=None,
  tree_root="apktool/", manifest_relative="AndroidManifest.xml",
  coverage=None, diagnostics=None) -> list[dict]`. Every edge is exactly
  `{edge_type, from, to, citations:[cite, cite]}`; every cite is an
  `EvidenceLocation` serialized by `contracts.citation_to_dict`, so the
  round-trip `EvidenceLocation(**cite) == cite` holds (tested). One-sided
  relations stay in the facts plane: no half-edges.
- Edge types and how they are derived (existing P0–P3 data only, never a
  re-parse and never similarity):
  * `component->class` — `manifest_v2.components[]` x `dex.class_model`;
    cites `manifest_component` (xpath) + `dex_class`. Unresolved class =>
    diagnostic `link_component_class_unresolved`, **no edge**.
  * `class->method` — `dex.class_model` + `dex.method_model` (already keyed
    by `full_name`), both cites from the DEX model.
  * `method->method` — `dex.internal_call_graph`; external callees are kept
    (they exist in that graph) and claim no `dex_index`.
  * `method->endpoint` — `dex.dex_api_strings` filtered to `urls` /
    `route_candidate` (the unfiltered list also emits class-name noise).
  * `endpoint->permission` — `dex.permission_api_usage` joined through the
    calling method to the endpoint it reaches; cite carries
    `extractor_coordinate = {permission, permissions, requested,
    manifest_path}` where `requested` is the per-edge answer.
  * `method->native` — the `native_jni_entry` facts `native.py::_map_jni_symbol`
    already wrote (`.so` byte offset + smali line + `mapping_confidence`).
    No re-demangling; the JNI matcher is reused, not duplicated.
  * `native->secret` — only when TruffleHog findings are supplied (the
    pipeline does not pass them yet). Absent => coverage
    `link_type_native_secret = "not_applicable"` + diagnostic
    `link_native_secret_source_absent`.
  * `asset->reader` — provably not derivable from static data:
    `link_type_asset_reader = "not_applicable"` + diagnostic
    `link_asset_reader_not_derivable`. Never guessed.
- `build_entry_points(surface_result, dex_result, *, tree_root=...)`:
  exported components, deep-link targets, MAIN+LAUNCHER, and the
  `android:name` Application class; each record says `exported`,
  `externally_reachable`, `reachability[]`, `intent_actions`, `deep_links[]`,
  `class_descriptor`, `class_in_dex`, `declared_permission(_requested)`,
  `class_citation`.
- `write_links(output_dir, edges, entry_points)` -> `{"links", "entry_points"}`.
  Atomic temp+fsync+chmod 0600+`os.replace` pattern copied from
  `apk_surface.py::_parse_resources_to_disk` (`.{name}.tmp-{pid}`); a failed
  write leaves nothing behind and never touches `facts.jsonl`.

**Decision — links are NOT folded into `FactStore`** (rationale in the module
docstring): a fact dedups by value and carries `count` = occurrences, an edge
is a relation between two proven locations. Publishing one relation in two
planes invites drift. If it is ever folded, it must go through
`FactStore.add(..., extra=...)` so `RESERVED_FACT_KEYS` rejects overwrite.

**Wiring** — `apk_surface.py::run_static_surface_analysis`, between the DEX
stage and `finalize_result` (mirrors the handoff block): merges
`link_coverage` into `result["coverage"]`, appends link diagnostics, sets
`metrics.link_edge_count` / `metrics.entry_point_count`; on `OSError` the
artifact goes `partial` with `link_write_failed` and the reason is kept.

**Fixture** — extended, not invented: `tests/fixtures/dexfixture/` gained
`Api.smali` (endpoint constant + `LocationManager.getLastKnownLocation`),
`App.smali`, `SyncService.smali`, `Main.onCreate -> Api.fetch`, and a manifest
with `ACCESS_FINE_LOCATION`, an Application name, a `https/app.example.test/feed`
deep link and an exported service behind `BIND_JOB_SERVICE`; APK rebuilt with
apktool 2.7.0. The `.so` is **not** committed (`lib/` is gitignored); tests
copy the decode tree and synthesize `lib/arm64-v8a/libdexfixture.so` with
`tests.elf_fixtures.write_elf`.

**Bug the tests caught (in the new code)**: `_endpoint_edges` first returned
endpoint -> {callers}, which made `endpoint->permission` emit zero edges.
Correct direction is caller -> {endpoints}; fixed before the first green run.

**Exit criteria — all three answered from `links.jsonl` +
`entry_points.jsonl` on the real fixture** (`tests/test_surface_links.py`):
1. `component:activity:com.example.Main` -> `class:Lcom/example/Main;`,
   `exported=true`, reachability `{exported, launcher_activity, deep_link}`,
   deep link `https://app.example.test/feed`; `SyncService` exported behind
   `BIND_JOB_SERVICE` (`requested=false`); Application `com.example.App`
   resolves to `Lcom/example/App;`.
2. `endpoint:https://api.example.test/v1/feed` called by
   `method:Lcom/example/Api; fetch ()Ljava/lang/String;`; the caller side
   `method:Lcom/example/Main; onCreate ()V -> Api.fetch` plus
   component->class->method is the entry-point chain.
3. `endpoint->permission` emits **both**
   `ACCESS_FINE_LOCATION` (`requested=true`) and
   `ACCESS_COARSE_LOCATION` (`requested=false`) — never collapsed, never
   dropped because the manifest omits one.

**Determinism** — edges are de-duplicated on canonical JSON and sorted, so
output is stable across processes: `PYTHONHASHSEED=0/1/12345` on the fixture
all give `sha256=f2246ff3141d…`, 42 edges, 3 entry points. (D19 still makes
the *upstream* `internal_call_graph` order vary; links does not inherit it.)

**Remaining observations (rechecked 2026-11-17)**: the Application class is an
entry point with its own `class_citation` but has no `component->class` edge
(it is not in `manifest.components[]`); a walker starts from the entry point.
M1 now refreshes the link/trace outputs after scanning and differentiates
successful-empty, failed, missing, and not-run scans. Smali file-to-class
mapping uses the DEX slash-form descriptor. `caller_class` / `callee_class`
and `asset->reader` relationships must be rechecked against current code
before considering D20 or related gaps closed.

### P5 — Detection breadth (implemented)
`CODE_RULES` grew from 19 to 29 rules, with `docs/rules.md` and positive /
negative fixtures. Endpoint and route findings are rolled up by normalized
pattern while facts retain occurrences and citation samples. D2, D3, and D9
are fixed. Do not treat this as comprehensive vulnerability detection; rules
are static leads with evidence, not runtime verdicts.

### P6 — Containers and packed code (implemented)
`extract_embedded_code` streams bounded `.dex` / `.jar` / `.apk` members,
recurses nested containers to a diagnosed depth limit, and feeds embedded DEX
payloads to Androguard with `container!member` source citations. Container
limits and unreadable/depth-limited members are diagnostics, not silent skips.
This does not cover arbitrary non-zip encrypted/custom packers.

### P7 — Scale
Single-pass streaming writes, bounded memory, per-file checkpoint
(`surface/checkpoint.py` exists and is unused), shard by natural unit.
Exit: the 112k-file case completes inside the RAM budget and resumes after a
kill. Measured baseline: 57,944/112,254 files at ~39 files/s, killed at
1,481 s with nothing persisted (`todo.md` history).

**P7 — DONE** (worktree):
- `analyze_apk_surface` gains `checkpoint_dir` parameter. Checkpoint saves
  every CHECKPOINT_EVERY_FILES (25) files, recording processed_files for
  crash-resume. On restart, already-swept files are skipped.
- FactWriter streams per-file results to `facts_stream.jsonl` in output_dir
  (single-pass streaming writes; no full-result accumulation before write).
- `MAX_SINGLE_FILE_BYTES` (50 MiB) size guard on per-file read_text in the
  sweep loop (D15). Larger files streamed line-by-line via `_stream_sweep_file`
  in chunks of SWEEP_STREAM_CHUNK_LINES (10k lines), preserving real line
  numbers for evidence cites.
- Native overflow sharding already handled by native.py ShardWriter
  (shards.py + shards-index.json pattern from P0).
- D7 fixed: load-site map (`known_names`) keyed on full relative path, not
  basename. `basename_to_citation` fallback resolves load values (filenames
  only) to full paths. Two same-named .so in different dirs stay distinct.
- D15 audited: all 12 `read_text` call sites reviewed. Only the sweep loop
  (`apk_surface.py` per-file read) needed a size guard; others are bounded
  (config, markers, small manifests) or not in the sweep hot path.

### P8 — Handoff (partial)
Implemented: `static-analysis.json` under `surface/` with legacy reader
fallbacks; `handoff.json`; `hashes.sha256`; read-only evidence freeze;
`verify-workspace`; CLI verification tests and pipeline-freeze tests
(`72f2d7d`, `tests/test_workspace_freeze.py`,
`tests/test_pipeline_integration.py`).

Not yet demonstrated: one representative real-app bundle successfully
consumed by prompts 0..6; a canonical volume hierarchy for large location
maps; enforced schemas for AI outputs; and bundle-level aggregation across
split components. See `oc-handoff/99-briefing.md` and the product rescue board.

--------------------------------------------------------------------------------
## 2. DEFINITION OF DONE (the scanner is "360-ready" when...)
--------------------------------------------------------------------------------
An AI can answer these **from the bundle alone, with a citation**:

1. Who signed it, with what certificate SHA-256, under which scheme? — **DONE (P1)**
2. Package, version, SDK range, ABI set, split set, install size? — partial (ABIs/SDKs yes; split set is bundle-level, P8)
3. File count, how many analysed, and for each skipped file: why? — **DONE (P0)**
4. What classes exist, how many methods each, where declared? — **DONE (P3)**
5. Which component is exported, which class implements it, what can invoke it? — **DONE (P4)**
6. Which endpoint is called by which method, from which entry point? — **DONE (P4)**
7. Which permission gates that path, is it requested? — **DONE (P4)**
8. Which native library implements which declared method, who calls it? — **DONE (N1-N13)**
9. Which secret exists, in which file/offset/method, who uses it? — partial (native only)
10. What could the scanner not see, and what is the evidence? — partial (coverage + ledger; packed/encrypted evidence is P6)

--------------------------------------------------------------------------------
## 3. AUDIT DEFECT LEDGER (D1-D18) — keep this current
--------------------------------------------------------------------------------
| # | Defect | Status |
|---|---|---|
| D1 | `resource_inventory=success` without parsing | **FIXED** P0 |
| D2 | `packed_indicator` deduction has no evidence | **FIXED** P5 |
| D3 | `obfuscation_metric` deduction has no evidence | **FIXED** P5 |
| D4 | external methods without callers dropped, metric hides it | **FIXED** P3 (emitted with `call_sites=[]`, counted in `external_methods_without_callers`) |
| D5 | DEX strings deduped by value, DEX-of-origin lost | **OPEN** (recheck whether current `dex_source` handling closes this for all top-level DEX strings) |
| D6 | stripped-section ELF yields no symbols despite `PT_DYNAMIC` | open (P3/native) |
| D7 | load-site map keyed on basename only | **FIXED** P7 (full relative path plus basename fallback) |
| D8 | `text_file_limit` / `finding_limit` referenced, never emitted | **FIXED** P0 |
| D9 | one finding per endpoint/route (inventory noise) | **FIXED** P5 (rollup: one finding per pattern + occurrence_count + citation sample; facts plane unchanged) |
| D10 | `SENSITIVE_PERMISSIONS` dead duplicate in `apk_surface.py:53` | open |
| D11 | unhardened `DOMAIN_RE` (ReDoS) x2 | **FIXED** P0c |
| D12 | `manifest_v2.py` severity if/else identical | open |
| D13 | run marker writes `eligible=0` before computing it | **FIXED** (refresh immediately after eligible list is computed) |
| D14 | `finalize_result` runs twice per artifact | open |
| D15 | whole-file `read_text`, no size guard, no streaming | **FIXED for sweep hot path** P7; remaining reads are bounded/outside sweep per audit |
| D16 | no per-file status ledger | **FIXED** P0 |
| D17 | facts/ledger written at artifact root, not `surface/` | **FIXED** (surface outputs relocated; legacy root readers retained) |
| D18 | only 3 driver-level tests | improved (301 total) |
| D19 | `internal_call_graph` / `call_sites` / `dex_api_strings[].references` order comes from set iteration -> two runs are byte-different (content identical) | open (found in P3 verification, pre-existing at HEAD; P4 output is unaffected, it sorts edges) |
| D20 | `asset->reader` has no provable derivation — assets are inventoried but no edge says who reads them | open (P5; P4 records `link_type_asset_reader=not_applicable` + diagnostic, never a guess) |
| D21 | surface stage cannot see TruffleHog findings (trufflehog runs after surface), so secret links are absent in a pipeline run | **FIXED** (M1 refreshes links and trace chains after scanning; successful-empty, failed, missing, and not-run states are tested) |

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
- Links stay a separate plane: `links.jsonl` edges are relations, not facts;
  they are never folded into `FactStore` (a fact dedups by value + count, an
  edge is a pair of proven locations). Folding later requires
  `FactStore.add(..., extra=...)` so `RESERVED_FACT_KEYS` guards it.
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
| DEX | `tests/test_androguard_dex.py` | 12 |
| links + entry points | `tests/test_surface_links.py` | 12 |

Scanner-related tests: 170 of the 341 collected. Hermetic fixture builders:
`tests/elf_fixtures.py`, `tests/identity_fixtures.py`, `tests/arsc_fixtures.py`,
`tests/fixtures/dexfixture/` (real 1.8 KB APK + the smali sources it was built
from, used by the code-model tests).

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
| `3de13fe` | P3: `class_model` / `method_model` / `string_class_index` / `reflection_sites`, `dex_class` on every edge, D4 fixed (+8 tests, real APK fixture) |
| `2c3d535` | P4: `links.jsonl` (8 typed edge types, two `EvidenceLocation` cites each) + `entry_points.jsonl`, atomic write, pipeline wiring, +12 tests on the real fixture |
Memory-only commits interleaved: `a7aa2af`, `eadf73d`, `45bec3e`, `cb52d53`,
`9a2f8f1`.
Push state: `origin/feat/native-elf-reader` tracks HEAD, and on 2026-11-16
`main` was fast-forwarded to the same tip and pushed (no force). `main`,
`origin/main` and the feature branch are one commit. New work continues on
`feat/native-elf-reader`; fast-forward `main` again when it is accepted.
