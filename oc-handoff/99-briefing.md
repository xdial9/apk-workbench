# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-23
**Repository:** `main` (post-`dc1872e`, local commit pending/recorded at commit)
**Tests:** `.venv/bin/pytest -q` and fresh-venv `pip install -e '.[dev]' && pytest -q` — **431 passed, 0 failed**; `git diff --check` — passed.
**Next:** Operator decisions on Defect 12 (`security/` full crypto verifier vs leaving placeholder), Defect 13 (delete dormant `registry.py` / `executor.py` / `trufflehog_adapter.py` / `database/evidence.py`), and Defect 14(d) (`sources/google_play.py:58` stray docstring).

## Current state

- **Unit 1 / Handoff Layout (Defect 1) — Complete**: All surface outputs (`static-analysis.json`, `facts.jsonl`, `location_map.json`, `files.jsonl`, `resources.jsonl`, `links.jsonl`, `entry_points.jsonl`, `trace_chains.jsonl`, `shards/`) now write under `surface/`. `apk_surface.py` and `workspace.py` populate `manifest/` (`google-play-bundle.json` + `provenance.json`/`status.json`) prior to `freeze_evidence` and `handoff.json`. `workbook.py` and `final_run.py` match disk layout; `verify-workspace` passed on all 4 `com.simplemobiletools.calculator` v85 E2E bundles (`0` mismatches/missing/extra/writable evidence).
- **Prompts Dry-Run (Defect 4) — Complete**: `prompts/0.txt..6.txt` were dry-run read-only against real frozen `calculator-85` bundles (`base` and `arm64_v8a`), aligning all paths (`surface/...`, `manifest/...`, `prompts/...`, `trufflehog/...`, `ai_analysis/attempt-01/`), replacing nonexistent `manifest_facts` with real `surface/static-analysis.json` keys, and adding large-file and split-APK guidance.
- **Stripped ELF Symbol Recovery (Defect 2 / D6) — Complete**: `native_elf.py` now falls back to `PT_DYNAMIC` (`DT_SYMTAB`, `DT_STRTAB`, `DT_STRSZ`, `DT_SYMENT`, `DT_HASH`, `DT_GNU_HASH`) + `PT_LOAD` vaddr-to-offset translation when section headers are absent (`e_shoff=0`), recovering exports, imports, and dynamic string entries with bounded reads (`MAX_SYMBOLS=500_000`, `MAX_STRINGTABLE_BYTES=32MB`). Verified on stripped `calculator-85` arm64 `.so`s (`2,004` exports, `160` imports, `7` JNI exports).
- **Resume & CLI (Defect 3) — Complete**: `run_static_surface_analysis` wires `checkpoint_dir = surface_dir / ".checkpoint"` + `sweep_state.json` (insertion-ordered, `CHECKPOINT_EVERY_FILES=2000`, `CHECKPOINT_EVERY_SECONDS=15.0`) + `FactWriter` streaming, resetting on `force=True` and cleaning transient files on completion. Added `apkworkbench surface`, `run --force-surface`, and fixed `force_surface.py` to forward to `["surface", "--force", *args]`. Verified mid-sweep and post-sweep `SIGKILL` + resume on `calculator-85`.
- **DEX, Manifest, Deductions, and Warts (Defects 5–11, 14) — Complete (except 14d)**:
  - `androguard_dex.py`: preserves `dex_index`/`dex_indices` on merged `dex_api_strings` (D5); adds explicit `confidence="hint"` and `resolution_method="nearest_preceding_string_heuristic"` on reflection sites (14c). (`test_androguard_dex.py` FakeDex issue was already fixed on `main`.)
  - `manifest_v2.py` + `deductions.py`: consolidated canonical `SENSITIVE_PERMISSIONS` (`PERMISSION_MISMATCH_CANDIDATES` preserving 12-perm mismatch semantics), deleted dead `apk_surface.py` copy (D10) and dead `manifest_v2.py` `if/else` (D12).
  - `apk_surface.py` + `final_run.py`: removed premature initial `eligible=0` marker write (D13), collapsed duplicate `finalize_result` calls (D14), wired `native_skipped` into `build_file_ledger` (14b), and replaced inline `__import__("datetime")` (14e).
  - `native.py`: renamed `native_strings_scanned` -> `native_libraries_strings_scanned` (14a).
  - `cli/main.py`, `scripts/full_google_play_pipeline.sh`, `requirements.txt`, `sources/__init__.py`, `decompilation/runner.py`, `core/config.py`, `dependencies/detector.py`, `pyproject.toml`: fixed stale banners/comments/requirements (11), narrowed `accepted_codes` to `0..255` (14f), preserved `defaults["sources"]` keys (14g), added `androguard_timeout_seconds: 1800` default (14h), resolved venv `androguard` binary when PATH excludes `.venv/bin` (14i), and added `pythonpath = ["."]` to `pyproject.toml`.

## Open decisions (untouched by design)

1. **Defect 12 (`security/__init__.py`)**: Documented as a retired OpenPGP placeholder pointing to `acquisition.verification` and `analysis.surface.identity`. Full v1/v2/v3 cryptographic APK signature verification requires `cryptography` (or `apksigner`) and ~300–500 LOC (>200-LOC threshold).
2. **Defect 13 (Dormant Phase-C framework)**: `registry.py`, `executor.py`, `trufflehog_adapter.py`, `database/evidence.py` (2,664 src+test LOC, 0 live callers) remain untouched; deletion is recommended over wiring in (+800–1,400 LOC, conflicts with cancelled rewrite D-6), while keeping `EvidenceLocation` (`contracts.py`) and `checkpoint.py`.
3. **Defect 14(d) (`sources/google_play.py:58`)**: Stray docstring literal in `GooglePlayAuthenticationError.__init__` left untouched per DO NOT TOUCH guardrail on acquisition modules.

## Guardrails

- Do not mutate the original frozen Calculator bundles in `~/APK-Workbench/workspace*`.
- Do not run the full Spotify heavy case or work in tmpfs (`/tmp/opencode/ws`).
- Do not remove caps to avoid truncation; count, shard, and report partial coverage.
- Keep secrets out of ordinary human-readable summaries.
- Preserve the unrelated untracked `ai-memory/test.txt`.
