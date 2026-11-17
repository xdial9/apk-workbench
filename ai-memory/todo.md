# RESUME FILE — APK-Workbench (current state 2026-11-17)

**Current snapshot:** `main` at `5f7b465`; `.venv/bin/python -m pytest -q`
reports 381 passed. Scanner P0-P7 are implemented. The per-bundle evidence
freeze, handoff manifest, and `verify-workspace` are implemented and
fixture-tested; Unit 1 is complete in code. The current delivery sequence is
the product rescue board at `docs/engineering/PRODUCT-RESCUE-BOARD.md`.

The original Unit 1 design and historical notes below are retained for context,
but their old status/phase ordering is superseded by this current snapshot.
Read `ai-memory/scanner-plan.md` and the rescue board before starting code.

Read this first, then INDEX.md "CANONICAL DESIGN DECISIONS" (D-1..D-9),
then appdev.txt §1 + §14 + §15. This file is the hands-on handoff; INDEX is
the contract.

Operating rule agreed with the user: ONE PHASE AT A TIME. Complete it, stop,
report. The user reviews before the next phase starts. Do not push unless
asked.

--------------------------------------------------------------------------------
## CURRENT STATE — verified 2026-11-17
--------------------------------------------------------------------------------
- Branch/revision: `main` at `5f7b465` (main is ahead of `origin/main` by one
  commit at this snapshot; do not push without explicit instruction).
- P0-P7 are implemented. Unit 1 bundle freeze and `verify-workspace` are
  implemented in code and covered by `tests/test_workspace_freeze.py` and
  `tests/test_pipeline_integration.py`.
- Native ELF/JNI analysis, cross-APK JNI matching, typed links, and trace
  chains exist. Commit `5f7b465` passes retained TruffleHog findings into
  `build_link_graph`; its failure-state handling and full pipeline behavior
  still need targeted tests.
- P8 is partial: a model dry-run, enforced output schemas, large-volume
  hierarchy, and split-component bundle aggregation remain unverified.
- No representative result bundle was found in the repository. The external
  configured workspace has not been inspected; real-app report quality is
  therefore unverified.
- M0 current-state synchronization is complete in this change and will be
  committed with the board and memory updates. Next: verify/fix the post-scan
  secret-link integration (M1). Do not begin broader enhancements until that
  gate is met.

--------------------------------------------------------------------------------
## HISTORICAL PHASE ORDER — superseded by the product rescue board
--------------------------------------------------------------------------------
0. DONE  — commit the handoff writers (6e8dcaf).
0b. DONE 2026-11-16 — citation-root parameter (D-1 step 2). Committed+pushed.
1. DONE  — PER-BUNDLE WORKSPACE + FREEZE (implementation present; see
           `oc-handoff/99-briefing.md` and `tests/test_workspace_freeze.py`).
2. NEXT  — Verify post-scan TruffleHog-to-link/trace integration (board M1).
3.       — Make native evidence visible in final report (board M2).
4.       — Produce and inspect one complete bundle/report (board M3).
5.       — Fix ONLY what the dry run proves: expect volume hierarchy, evidence
           precedence, output schema gate.
6.       — Phase A ceilings, done as STREAMING to disk (not deletion): box has
           3.8GB RAM. Deleting the 64MB androguard cap converts truncation
           into OOM. Same for trufflehog's buffers. Keep heartbeats.
7.       — Optional: single-pass trufflehog verified+unverified split (D-5).
8.       — Phase D dossier -> Phase E corpus -> Phase F per-run isolation.
           Phase C rewrite is CANCELLED (D-6). Analyzer changes from here are
           measurement-led and targeted only.

--------------------------------------------------------------------------------
## UNIT 1 SPEC — PER-BUNDLE WORKSPACE + FREEZE (implemented; historical spec)
--------------------------------------------------------------------------------
Goal: one app version bundle gets ONE self-contained, frozen, portable folder
that matches what prompts 0..6 promise, without duplicating the decoded tree.

### Layout to produce
```
results/<package_id>/<version_code>/<bundle_id>/
  apktool/base/                     decoded base.apk
  apktool/split_config.arm64_v8a/   decoded splits (one dir per component)
  apktool/split_config.en/
  apktool/split_config.xxhdpi/
  surface/static-analysis.json      per-artifact aggregation (see OPEN)
  surface/facts.jsonl
  surface/location_map.json
  trufflehog/findings.json | status.json
  manifest/                         run-manifest row(s) + google-play-bundle.json
  0.txt .. 6.txt                    instruction chain copied at freeze
  README.txt                        what this is + how to start
  handoff.json                      schema/tool/prompt versions + hashes
  ai_analysis/attempt-01/           ONLY writable area
```
- bundle_id = run manifest `index_sha256`. VERIFIED on run c79180cf: all four
  Spotify rows share 6ae4f3aa267c77312806a652ef299833c0ac38bfd52d6c21121cd509a36c56c6.
- Original APKs stay in downloads/<pkg>-<version_code>/; never moved.
- Missing stage => write status.json (status + reason). Never leave a promised
  path absent.

### Freeze (no copy, no hardlink, no symlink)
- chmod evidence read-only: apktool/, surface/, trufflehog/, manifest/.
- write hashes.sha256 over frozen files.
- new `apkwb verify-workspace <folder>`: recompute, report mismatches/missing/
  extra; exit non-zero on tampering; never write into the folder.
- ai_analysis/attempt-01/ stays writable.

### Required code changes (with reasons)
1. Driver/finalizer: write into the bundle path, component subtrees. Existing
   results/<pkg>/<ver>/<digest>/ artifacts are NOT migrated (see OPEN).
2. surface/handoff.py: replace the hardcoded "apktool/" citation prefix with a
   parameter carrying the component tree root ("apktool/base/",
   "apktool/split_config.arm64_v8a/", ...). location_map.json AND
   workbook.location_ledger must cite the real component path.
   DONE 2026-11-16: `tree_root` parameter, driver derives it from the layout.
3. static-analysis.json moves under surface/. Update the only two readers
   (reporting/final_run.py:368, database/workspace.py:327) to try the new path
   first and fall back to the legacy root path; add tests.
4. Run marker: refresh `eligible` immediately after computing it (today it
   stays 0 until an artifact completes, which made a live run look dead).
5. Freeze step + handoff.json + README.txt + prompts copy + ai_analysis/.
6. `apkwb verify-workspace` command + tests.

### Open decisions — resolve with the user before coding
- LAYOUT (asked 2026-11-16, awaiting one-line answer): static-analysis.json /
  facts.jsonl / location_map.json under a real surface/ dir (prompts 0/2 and
  workbook.py already promise it; recommended YES); google-play-bundle.json
  stays at the bundle root (three consumers expect it; recommended YES,
  contradicts D-3's manifest/ wording).
- Bundle-level aggregation of per-APK static-analysis.json. Proposal:
  surface/artifacts/<sha256>/static-analysis.json per APK plus a bundle-level
  surface/bundle.json index. A silently merged JSON is NOT approved.
- Migrate existing results trees, or apply the new layout to new runs only?
  Recommendation: new runs only; the analyzer version gate already forces
  stale artifacts to re-analyze.

### Exit criteria for Unit 1
- One real bundle (single-APK app is fine) freezes into the layout above.
- Every path named in prompts 0..6 exists or has a status.json.
- Citations in location_map.json resolve to real files/lines from the folder.
- verify-workspace passes on an untouched folder and fails after a deliberate
  edit inside apktool/.
- Reconcile + final report still read artifacts correctly (legacy fallback
  covered by a test).
- 213+ tests green; no changes to result semantics.

--------------------------------------------------------------------------------
## UNIT 2 — DRY RUN (after Unit 1 is accepted)
--------------------------------------------------------------------------------
1. Acquire + decode + analyze ONE single-APK app; freezes into Unit 1 layout.
2. Hand the folder to a capable model with 0.txt. Record every deviation
   verbatim: unresolved path, ambiguous step, skipped stage, token blowout,
   invented file, uncited claim.
3. Check its ai_analysis/ output against workbook.finish_line.
4. Turn deviations into the Unit 3 work list. Do not pre-emptively build
   volume hierarchy or schema gates before seeing the real failures.

--------------------------------------------------------------------------------
## ENVIRONMENT
--------------------------------------------------------------------------------
- Repo /home/user/APK-Workbench; venv .venv/bin/python.
- Product workspace default: ~/APK-Workbench/workspace (ext, 633GB free).
- DEV FIXTURE: /tmp/opencode/ws is TMPFS (1.9GB total, ~337MB free). The
  1.1GB Spotify tree lives in RAM/swap. Move the fixture to disk before any
  batch/bundle work; a copy of that tree cannot fit in /tmp.
- apktool 3.0.3; trufflehog 3.99.8; androguard 4.1.4 pinned.
- Machine: ~3.8GB RAM (this is why Phase A must stream, not un-cap blindly).

--------------------------------------------------------------------------------
## KNOWN-GOOD REPLAY ARTIFACTS
--------------------------------------------------------------------------------
- /tmp/opencode/antennapod-before.json (pre-perf, 03:32)
- /tmp/opencode/antennapod-after.json (optimized surface-only)
- /tmp/opencode/bench_sweep.py (300-file speed/parity harness)
- Antennapod decoded tree:
  /tmp/opencode/ws/results/de.danoeh.antennapod/3120395/7697f3aa.../apktool
  (138MB; the only finished surface artifact)
- Spotify decoded trees: /tmp/opencode/ws/results/com.spotify.music/148387875/
  (base 1.1GB + 3 small splits; no analysis output persisted)

--------------------------------------------------------------------------------
## HISTORY OF THIS SESSION (what actually happened)
--------------------------------------------------------------------------------
1. Profiled the live Spotify sweep; ~43% of CPU was per-line marker loops.
2. Optimized surface/sweep.py (062973b): compiled matchers, file-level
   dependency evidence, required-character gates, per-file suffix.
   300 real smali files 16.73s -> 6.02s; full Antennapod 407s.
3. Parity verified against the pre-change artifact: findings 4299, endpoints
   2507, manifest/inventory/deductions/sdk_histogram/fact core identical.
4. Restarted the Spotify heavy case on the optimized code; user stopped it at
   57,944/112,254 files. Recorded as throughput only, not validation.
5. Design review with the user produced the canonical decisions D-1..D-9
   (per-bundle workspace, in-place freeze, no rewrite, trufflehog scope,
   size policy, tmpfs warning, process rules).
6. Implemented + committed the handoff writers (6e8dcaf) with 6 tests.
7. 2026-11-16: parameterized the citation root (tree_root) in
   handoff/workbook/serialize/apk_surface + 2 tests; 213 green; committed and
   pushed. No layout move yet, so behavior is unchanged.
8. Remaining unknowns: bundle-level aggregation, layout answer (surface/ vs
   root), and whether the prompt chain survives first contact with a real
   model. Resolved in Units 1-2.

--------------------------------------------------------------------------------
## TRIPWIRES
--------------------------------------------------------------------------------
- Do not run analyze_apk_surface for parity and expect DEX/zip sections; it
  does not run them. Compare surface sections only.
- Any new regex family needs its required-character gate + a parity test
  (the colon-free [deadbeef] case is the cautionary example).
- Handoff evidence paths are tree-relative in static-analysis.json and
  folder-relative in location_map.json. Do not conflate them; under the
  bundle layout the root is apktool/<component>/, not apktool/.
- The run marker only refreshes after an artifact completes; a mid-sweep stop
  leaves it saying "running". Treat stale markers as unknown, not alive.
- A second trufflehog scan is NOT approved (D-5). Verified-only is the design.
- Do not start a full rewrite (D-6). Targeted, measured changes only.
- Do not edit code while the user is asking a question. Answer, then ask.
- Do not push without an explicit request.

--------------------------------------------------------------------------------
## OPTIONAL: RERUN THE SPOTIFY HEAVY CASE (not required for Unit 1)
--------------------------------------------------------------------------------
Only if heavy-case evidence is needed again. Nothing was persisted, so this is
safe. Move the workspace off tmpfs first (D-8), otherwise it will swap hard.
```
cd /home/user/APK-Workbench
export APKWORKBENCH_WORKSPACE=/tmp/opencode/ws
export APKWORKBENCH_CONFIG_DIR=/tmp/opencode/cfg
export APKWORKBENCH_STATE_DIR=/tmp/opencode/state
.venv/bin/python - <<'EOF' > /tmp/opencode/surface_spotify_optimized.log 2>&1
import json, time
from apkworkbench.core.config import Config
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.analysis.apk_surface import run_static_surface_analysis

config = Config()
workspace = config.get("workspace")
database = WorkspaceDatabase(workspace)
start = time.monotonic()
summary = run_static_surface_analysis(
    database, workspace,
    run_id="c79180cf-01ab-4b2b-a507-4e238f24c1d1",
    progress=lambda m: print(m, flush=True),
)
print("=== SURFACE SUMMARY ===", flush=True)
print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"}, indent=1))
print(f"WALL_CLOCK_SECONDS: {time.monotonic() - start:.1f}", flush=True)
EOF
```
