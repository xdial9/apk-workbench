# OC-Handoff Briefing — Unit 1 (Per-Bundle Workspace + Freeze) Complete

NOTE: AGENTS.md requests this file at `/home/user/oc-handoff/99-briefing.md`.
That path is absent and unwritable in this environment (`/home/user` does not
exist; session user is `dial9`). Written here instead so the promised path
exists inside the bundle workspace.

## State (as of 2026-11-17, Unit 1 completion)
- Branch: agent-work (based on feat/native-elf-reader); main == origin/main as of 2026-11-16 push.
- P0–P7 committed. Unit 1 (P8 handoff freeze + workspace) DONE in worktree (this phase).

## Unit 1 deliverables

### Static-analysis.json relocation to surface/ (D-3)
- `analyze_apk_surface` now writes `static-analysis.json` to `output_root / "surface" / "static-analysis.json"`.
- Legacy root path fallback retained for backward compatibility:
  - `reporting/final_run.py` reads `surface/` first, falls back to root.
  - `database/workspace.py` `reconcile_run` checks `surface/` first, falls back to root.
- Tests updated: `test_surface_links.py`, `test_pipeline_integration.py`, `test_surface_serialize.py`.

### D13: Eligible marker refresh
- `marker_refresh("running", ...)` called **immediately** after computing the eligible artifact list, not after the first artifact completes. Fixes the "live run looks dead (eligible=0)" bug.

### Freeze + hashes.sha256 (D-2 in-place freeze)
- `WorkspaceDatabase.freeze_evidence(bundle_dir)`:
  1. Writes `handoff.json` at bundle root (schema/tool/prompt versions + key file hashes + analyzer version + bundle_id).
  2. Walks entire bundle (excluding `ai_analysis/`, `database/`, and `hashes.sha256` itself), hashes all regular files, writes deterministic `hashes.sha256`.
  3. chmod evidence directories (`apktool/`, `surface/`, `trufflehog/`, `manifest/`) to **0o555** (read + execute for traversal); files to **0o444** (read-only). No copy, no hardlink, no symlink — the workspace IS the handoff folder.

### verify-workspace CLI command (read-only)
- `apkwb verify-workspace <folder>` added to `src/apkworkbench/cli/main.py`.
- Reads `hashes.sha256`, recomputes SHA-256 for every listed file.
- Reports mismatches, missing, extra (detects files added post-freeze, e.g., `surface/injected.txt`).
- Exits non-zero on any failure. **Never writes** into the verified folder.
- `WorkspaceDatabase.verify_workspace(folder)` returns dict with full details for programmatic use.

### handoff.json at bundle root
- `WorkspaceDatabase.write_handoff_manifest(folder, bundle_id, analyzer)` writes:
  - `schema_version: 1`
  - `bundle_id` (folder name / run manifest `index_sha256`)
  - `analyzer` (id + version)
  - `schema_versions` (facts_jsonl, location_map, static_analysis, workbook)
  - `tools` (androguard_dex: "4.1.4")
  - `prompts` (sha256 of each 0.txt..6.txt from repo `prompts/`)
  - `file_hashes` (from `hashes.sha256` or computed directly for key files)

### Six risk items audited (from INDEX.md HANDOFF READINESS ASSESSMENT)
| # | Risk | Status | Evidence |
|---|------|--------|----------|
| 1 | NEVER EXECUTED — prompts 0..6 not run by a model | **OPEN** | Handoff structure exists; dry run pending (Unit 2) |
| 2 | NO VOLUME HIERARCHY — location_map.json too large for model ingestion | **OPEN** | No sharding/indexing of location_map.json; deferred to Unit 3 |
| 3 | FOUR OVERLAPPING REPRESENTATIONS — static-analysis/facts/location_map/workbook | **PARTIAL** | All four exist; citation-root parameterized; need canonical precedence doc |
| 4 | NO ENFORCED OUTPUT CONTRACT — ai_analysis.json / lead_ledger / closure_report | **OPEN** | Prose-only schemas; no validation gate |
| 5 | NO FEEDBACK LOOP — closure report doesn't feed lead generation | **ADDRESSED (by design)** | Every run starts from zero after freeze; intentional per D-2 |
| 6 | DEX STILL CAPPED — 64MB androguard output cap | **CLOSED** | androguard_dex.py CAP-FREE since P0: _worker_entry writes full payload to disk |

## Test results
- **376 passed, 0 failed** (was 372 before Unit 1, +4 new freeze tests).
- ruff clean on all changed files.

## Commits (this worktree)
- 68fd6d6 — scanner P7: scale - checkpoint + streaming, D7 fix, D15 size guard
- c1854ea — scanner P6: fix coverage overwrite bug in embedded DEX wiring
- a6c6826 — scanner P6: containers and packed code (+5 fixture tests)
- 6ab63f5 — memory: P5 committed (detection breadth: 19 → 29 CODE_RULES)
- 8b98a36 — memory: P4 committed
- 2c3d535 — scanner P4: link graph + entry points (12 tests)
- 3de13fe — scanner P3: DEX code model + D4 fix
- ce766fe — memory: record main fast-forward to scanner tip
- 9a2f8f1 — memory: fill in real commit hashes, test map and commit log
- 4adb6a5 — scanner P2c: FileProvider roots + layout/view inventory (P2 complete)

## Next step
- **Unit 2 Dry Run**: Acquire + decode + analyze ONE single-APK app; freeze into Unit 1 layout; hand folder to a capable model with 0.txt. Record every deviation: unresolved path, ambiguous step, skipped stage, token blowout, invented file, uncited claim.

## Open decisions / unverified
- LAYOUT: `static-analysis.json / facts.jsonl / location_map.json` under `surface/` (prompts 0/2/workbook.py promise it); `google-play-bundle.json` stays at bundle root (3 consumers expect it; contradicts D-3's `manifest/` wording). **Recommendation: surface/ for analyzer outputs, root for google-play-bundle.json.**
- Bundle-level aggregation of per-APK `static-analysis.json`: proposal `surface/artifacts/<sha256>/static-analysis.json` per APK + `surface/bundle.json` index. No silently merged JSON.
- Migrate existing results trees, or apply new layout to new runs only? **Recommendation: new runs only; analyzer version gate forces re-analysis of stale artifacts.**
- D5/D6/D10/D12/D13/D14/D17/D19/D20/D21 remain open per audit ledger (D7, D15 now fixed; D13 marker refresh DONE; D17 relocation DONE).
- /home/user/oc-handoff/99-briefing.md path unavailable in this environment; this file is the substitute.