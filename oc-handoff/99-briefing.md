# OC-Handoff Briefing — P6 Containers and Packed Code (DONE)

NOTE: AGENTS.md requests this file at `/home/user/oc-handoff/99-briefing.md`.
That path is absent and unwritable in this environment (`/home/user` does not
exist; session user is `dial9`). Written here instead so the promised path
exists inside the bundle workspace.

## State (as of 2026-11-17, P6 completion)
- Branch: feat/native-elf-reader; main == origin/main as of 2026-11-16 push.
- P0–P5 committed (scanner truth plane, identity, resources, links, detection breadth).
- P6 containers and packed code DONE in worktree (this phase, pending commit).

## P6 deliverables (this phase)

### extract_embedded_code (src/apkworkbench/analysis/surface/native.py)
- Generalises `extract_embedded_libraries` cap/diagnostic structure to
  `.dex/.jar/.apk` members, parameterized on `member_suffixes`
  (default `(".dex", ".jar", ".apk")`).
- Constants: `CODE_MEMBER_SUFFIXES`, `MAX_CONTAINER_DEPTH=3`.
- `EmbeddedCode` dataclass: citation (full container chain), container, member,
  size, path, depth.
- Every cap is a diagnostic, never a silent drop (Completeness Law):
  - `code_container_unreadable` — bad zip
  - `code_container_member_limit` — too many members per container
  - `code_container_depth_limit` — zip-in-zip depth >= MAX_CONTAINER_DEPTH
  - `code_embedded_byte_limit` — member too large or total budget exceeded
  - `code_container_member_unreadable` — read failure
- Members streamed to disk in 1 MiB chunks (no OOM).
- Recursion into nested `.jar`/`.apk` containers up to `MAX_CONTAINER_DEPTH`;
  citation accumulates: `assets/plugin.zip!inner.jar!classes3.dex`.
- Temp files deleted after analysis (finally block).

### _analyze_dex_payloads (src/apkworkbench/analysis/androguard_dex.py)
- Core DEX analysis extracted from `_analyze_in_worker`, accepts raw dex bytes
  as `list[tuple[bytes, str | None]]` + `target_sdk`.
- Reuses exact `DEX(dex_bytes, using_api=target_sdk)` call from the top-level
  case.
- Every entry carries `dex_source` citation (None for top-level APK DEX,
  `container!member!nested.dex` for embedded):
  - `class_model`, `method_model`, `external_method_references`,
    `internal_call_graph`, `dex_api_strings`, `reflection_sites`,
    `string_class_index`, `permission_api_usage`.
- `_analyze_in_worker` unchanged (still works via multiprocessing from APK path).

### Wiring (src/apkworkbench/analysis/apk_surface.py)
- `code_containers` discovered from `tree.entries` (zip-like files).
- `extract_embedded_code` called; extracted .dex members read as bytes and fed
  to `_analyze_dex_payloads`.
- Results merged into `dex_analysis` (class_model, method_model,
  external_method_references, internal_call_graph, dex_api_strings,
  reflection_sites, permission_api_usage, string_class_index, metrics,
  diagnostics, limitations).
- Coverage key `dex_semantic_analysis`: "not_applicable" (no containers),
  "partial" (containers but all members skipped), or status from analysis.
- Works with or without a source APK file.

### Tests (tests/test_surface_embedded_code.py, +5)
- `test_zip_containing_dex_classes_cited_with_container_prefix` — .dex in zip,
  classes appear in class_model with `dex_source == "assets/plugin.zip!classes.dex"`.
- `test_container_nested_inside_container_resolves_to_depth_limit` — zip-in-jar,
  inner classes cited with full chain `assets/outer.zip!inner.jar!classes2.dex`.
- `test_depth_limit_produces_diagnostic_not_silent_stop` — MAX_CONTAINER_DEPTH=1,
  depth-limit diagnostic emitted, inner contents not scanned.
- `test_oversized_embedded_member_diagnostic_and_partial` — member over
  MAX_EMBEDDED_LIBRARY_BYTES, `code_embedded_byte_limit` diagnostic, coverage
  partial, no OOM.
- `test_embedded_code_temp_files_deleted_after_analysis` — temp files cleaned up.

## Test results
- 370 passed, 0 failed (was 365 before P6, +5 new).
- ruff clean on all changed files.

## Next step
- P7 Scale: single-pass streaming writes, bounded memory, per-file checkpoint
  (surface/checkpoint.py exists and is unused), shard by natural unit.

## Commits
- P6 commit: <hash pending — commit after this briefing is written>.

## Open decisions / unverified
- D5/D6/D7/D10/D12/D13/D14/D15/D17/D19/D20/D21 remain open per ledger.
- /home/user/oc-handoff/99-briefing.md path unavailable in this environment
  (noted above); this file is the substitute.
