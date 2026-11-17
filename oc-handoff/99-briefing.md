# OC-Handoff Briefing — P7 Scale (DONE)

NOTE: AGENTS.md requests this file at `/home/user/oc-handoff/99-briefing.md`.
That path is absent and unwritable in this environment (`/home/user` does not
exist; session user is `dial9`). Written here instead so the promised path
exists inside the bundle workspace.

## State (as of 2026-11-17, P7 completion)
- Branch: feat/native-elf-reader; main == origin/main as of 2026-11-16 push.
- P0–P6 committed. P7 scale DONE in worktree (this phase, pending commit).

## P7 deliverables (this phase)

### Checkpoint + streaming (src/apkworkbench/analysis/apk_surface.py)
- `analyze_apk_surface` gains `checkpoint_dir` parameter. `Checkpoint` saves
  every CHECKPOINT_EVERY_FILES (25) files, recording `processed_files` for
  crash-resume. On restart, already-swept files are skipped (not re-read from
  file zero).
- `FactWriter` streams per-file results to `facts_stream.jsonl` in
  `output_dir` (single-pass streaming writes; no full-result accumulation
  before write).
- `MAX_SINGLE_FILE_BYTES` (50 MiB) size guard on per-file `read_text` in the
  sweep loop (D15 fix). Larger files streamed line-by-line via
  `_stream_sweep_file` in chunks of `SWEEP_STREAM_CHUNK_LINES` (10k lines),
  preserving real line numbers for evidence cites.
- Native overflow sharding already handled by `native.py` `ShardWriter`
  (shards.py + shards-index.json pattern from P0).
- Final checkpoint saved with stage `sweep_done` (kept for resume; pipeline
  driver may delete after artifact fully processed).

### D7 fix (src/apkworkbench/analysis/surface/native.py)
- Load-site map (`known_names`) keyed on full relative path, not basename.
  `basename_to_citation` fallback resolves load values (filenames only) to
  full paths. Two same-named `.so` in different directories stay distinct.

### D15 audit (all `read_text` call sites)
Audited all 12 `read_text` call sites in `src/`:
1. `acquisition/verification.py:207` — bundle manifest JSON. Small, bounded. No change needed.
2. `reporting/final_run.py:25` — single run result JSON. Reporting path, not sweep. No change needed.
3. `reporting/generator.py:54` — findings JSON for report generation. Reporting path. No change needed.
4. `core/config.py:75` — YAML config file. Small, bounded. No change needed.
5. `database/workspace.py:270` — status marker JSON. Tiny. No change needed.
6. `database/workspace.py:348` — static-analysis.json. Could be large but not in sweep hot path. No change needed for P7.
7. `cli/main.py:346` — packages file. Small list. No change needed.
8. `trufflehog.py:549,554,567,568,615` — trufflehog results. Could be large but not in sweep. No change needed.
9. `apk_surface.py` per-file sweep loop — **FIXED**: `MAX_SINGLE_FILE_BYTES` guard + `_stream_sweep_file`.
10. `apk_surface.py:1481` — prior result read for reuse check. Not in sweep. No change needed.
11. `resources.py:99` — decoded res/values XML. Typically small. No change needed.
12. `checkpoint.py:53` — checkpoint JSON read. Tiny. No change needed.

### Tests (+2)
- `test_checkpoint_saves_processed_files_and_resume_skips` — checkpoint saves
  after every file; restart skips already-processed files (P7 exit criterion).
- `test_two_same_named_libraries_in_dirs_stay_distinct` — two same-named .so
  in different dirs stay distinct (D7 fix).

## Test results
- 372 passed, 0 failed (was 370 before P7, +2 new).
- ruff clean on all changed files.

## Next step
- P8 Handoff: `surface/` layout, bundle aggregation, workbook v2, prompts.

## Commits
- P7 commit: <hash pending — commit after this briefing is written>.

## Open decisions / unverified
- D5/D6/D10/D12/D13/D14/D17/D19/D20/D21 remain open per ledger (D7, D15 now fixed).
- /home/user/oc-handoff/99-briefing.md path unavailable in this environment
  (noted above); this file is the substitute.
