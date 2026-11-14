# SESSION SCRATCH / PAUSE HANDOFF — 2026-11-14

Status: deliberately paused by user after S8 performance fix. Read INDEX.md
first; this file holds the hands-on details for resuming.

## DONE THIS SESSION
1. Profiled the live Spotify sweep (py-spy): API-client marker loop ~28%,
   dependency-marker lower/any loop ~15%, code-rule loop ~7% of CPU.
2. Optimized `surface/sweep.py` (commit 062973b, tests 205 green):
   - compile client/rule matchers once per artifact;
   - dependency evidence once per matching FILE (old per-line appends were
     deduped by sorted(set(paths)), so exported facts are identical);
   - combined gate + required-character gates (://, :, ., [, quotes,
     invoke-, retrofit literal, base64 length);
   - suffix once per file; whole-file lowercase only in the dependency pass
     with an 8MB guard + case-insensitive regex fallback.
   - new tests: file-level dependency dedup; colon-free bracket parity.
3. Measured: 300 real Antennapod smali files 16.73s -> 6.02s (~2.7x);
   full surface-only Antennapod 407s for 15,290 files.
4. Parity verified against the pre-change Antennapod artifact:
   findings 4299 / endpoints 2507 / inventory / manifest / deductions /
   sdk_histogram / fact core all identical. Expected-only diffs: the 03:39
   fact-evidence fix (workbook ledger now populated) and the direct surface
   rerun lacking driver-only DEX + apk_inventory stages.
5. Aborted the pre-optimization Spotify run at 25,292/112,254 files,
   2,351s (~10.8 files/s baseline only; it is NOT validation evidence).
   Restarted the optimized run.

## CONFIRMED ANSWER: Spotify acquisition + scan state (2026-11-14 04:36)
- ACQUISITION COMPLETE, not in progress: `/tmp/opencode/ws/downloads/
  com.spotify.music-148387875/` holds 4 APKs, 131 MB total (base 101,256,400 B,
  arm64 split 34,145,588 B, en 1,069,465 B, xxhdpi 545,870 B) + 
  google-play-bundle.json. Acquired 03:08-03:09, signer 6505b181..., all
  hashes recorded in run_c79180cf-...csv.
- DECODE COMPLETE for all 4: results/com.spotify.music/148387875/<digest>/
  apktool/ trees exist (1.1 GB base, 33 MB arm64, 2.0 MB en, 844 KB xxhdpi).
- SCAN IN PROGRESS but only artifact 1 of 4 (base.apk, digest a6bded...).
  Evidence: log line "112,254 text files (108,190 smali)"; base tree has
  112,366 files total. Splits not yet analyzed.
- NO static-analysis.json written yet (find cmd returns nothing) and the run
  marker is still eligible:0/status:running, because the driver writes the
  artifact only AFTER sweep -> APK re-hash -> androguard DEX -> finalize.
  Absence of the file is expected, not a failure.
- Remaining driver stages for artifact 1: hash 101 MB base.apk (2s heartbeat),
  androguard DEX (dex_timeout_seconds=1800, and the 64 MB output cap will
  likely make it partial -> status partial, Phase A proof), then splits 2-4.

## STOPPED 2026-11-14 04:52 — Spotify heavy-case scan (user request)
- SIGTERM to PID 42219 at 04:52; process now a zombie (Z) reaped by its
  parent shell. The background shell reported exit 143 (SIGTERM).
- Final progress: 57,944 / 112,254 text files, 1,481s elapsed, 6,227
  endpoints, 4,890 findings — ALL IN MEMORY ONLY.
- NOTHING WAS PERSISTED: no static-analysis.json, no facts.jsonl, no
  location_map.json for any of the 4 Spotify artifacts (find returned
  nothing). Surface output is written only after sweep -> APK re-hash ->
  DEX -> finalize, and the sweep never finished.
- Marker results/runs/c79180cf-.../static-analysis-run.json still says
  "status": "running", eligible 0, no artifacts. STALE / DO NOT TRUST: the
  driver refreshes it only after an artifact completes. A future resume
  must not read it as evidence that a run is alive.
- Consequence: the heavy-case (131MB / 112k-file) validation is INCOMPLETE.
  Antennapod remains the only finished surface artifact. The measured
  throughput from this run is still valid evidence (57,944 files / 1,481s
  = ~39 files/s on the optimized code, vs 10.8 files/s before 062973b) and
  can be quoted as the heavy-case rate without claiming a completed run.
- Rerun command preserved below; it is safe to rerun (no partial artifact
  to corrupt).

## RUNNING NOW (optimized Spotify heavy case) — HISTORICAL, see STOPPED above
- PID 42219, launched 2026-11-14 ~04:26, run
  c79180cf-01ab-4b2b-a507-4e238f24c1d1.
- Log: /tmp/opencode/surface_spotify_optimized.log
- Workspace: /tmp/opencode/ws
- Expected: ~45-60 min total (112,254 text files / 108,190 smali, 1.1 GB
  decoded tree) + driver DEX/zip stages for the bundle.
- Check from a fresh shell:
    ps -p 42219 -o pid,etime,pcpu,rss,stat
    tail -5 /tmp/opencode/surface_spotify_optimized.log
    cat /tmp/opencode/ws/results/runs/c79180cf-01ab-4b2b-a507-4e238f24c1d1/static-analysis-run.json
    ls -la /tmp/opencode/ws/results/com.spotify.music/148387875/*/static-analysis.json
- If complete: record WALL_CLOCK_SECONDS (last log line) + summary JSON in
  INDEX §STATE and appdev §14; inspect whether the 4-APK bundle's large
  artifact emitted static-analysis.json and what coverage/DEX status says.
- If it died: rerun with the exact command below.

## EXACT RERUN COMMAND
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
elapsed = time.monotonic() - start
print("=== SURFACE SUMMARY (SPOTIFY 131MB, OPTIMIZED) ===", flush=True)
print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"}, indent=1), flush=True)
print(f"WALL_CLOCK_SECONDS: {elapsed:.1f}", flush=True)
EOF
```
(If run in a harness, background it and redirect; the here-doc process is
just `.venv/bin/python -`, so pgrep by that string.)

## PENDING USER DECISION (2026-11-14) — READ FIRST ON RESUME
Uncommitted work in the tree, left deliberately after the user objected to
edits being made during a direct question:
```
 M src/apkworkbench/analysis/apk_surface.py          (emit handoff files)
 M src/apkworkbench/analysis/surface/workbook.py     (tool_outputs + tree_root note)
?? src/apkworkbench/analysis/surface/handoff.py      (facts.jsonl + location_map.json)
?? tests/test_surface_handoff.py                     (6 tests)
```
Tests 211 green; ruff clean on changed files. Nothing is committed.
Options: (a) commit as-is, (b) keep working on it uncommitted, (c) revert.
Do NOT commit without explicit user approval.

## READINESS VERDICT (agent opinion, full text in INDEX.md + appdev §14)
Design on track; proof and budgeting not. Right and worth protecting: work
assignment not summary, enforced evidence discipline, raw-first law, nothing
hidden. Not on track, ranked: (1) prompt chain 0..6 has never been run by a
model on a real artifact; (2) no volume hierarchy for large apps (Spotify at
~31k files: ~4,000 endpoints, ~4,600 findings — location_map.json is not
model-consumable at that size); (3) four overlapping representations of the
same evidence invite double counting; (4) no schema gate on the AI's output;
(5) no feedback loop from closure report to lead generation; (6) DEX capped.
Recommended order: dry run -> volume hierarchy -> schema gate -> Phase A.

## NEXT WORK (in order)
1. **Handoff folder assembly.** Writers now exist (facts.jsonl +
   location_map.json next to static-analysis.json) but the prompts promise a
   HANDOFF FOLDER with `apktool/`, `surface/`, `trufflehog/`, `manifest/`,
   `google-play-bundle.json`, prompts 0..6, and a writable `ai_analysis/`.
   Nothing assembles that yet. Decide: build a handoff folder (copy/symlink
   policy) or rewrite prompts to the results layout. Plan v2 §5 favors the
   additive folder.
2. **Prompt-chain dry run on one real artifact** (highest-risk unknown).
   Cheap, will expose path/wording/step-ordering bugs before more code.
3. **Volume hierarchy**: ranked front page + stable pageable IDs for
   endpoints/findings, so a 4MB location_map never has to be ingested.
4. **Phase A ceiling removal.** The 64MB androguard cap fired on a NORMAL
   Antennapod app (dex partial) — empirical proof. Remove caps/timeouts
   per plan.txt Phase A; keep heartbeats.
5. **Output schema gate** for ai_analysis.json / lead_ledger.json /
   closure_report.md, so finish_line is enforced rather than suggested.
6. First active user run.

## KNOWN-GOOD REPLAY ARTIFACTS
- /tmp/opencode/antennapod-before.json (pre-change, 03:32)
- /tmp/opencode/antennapod-after.json (optimized surface-only)
- /tmp/opencode/bench_sweep.py (300-file speed/parity harness)
- Antennapod decoded tree:
  /tmp/opencode/ws/results/de.danoeh.antennapod/3120395/7697f3aaac42b7983b74263af7e6b3f7ac37412093fe53fe446ad693d92d58da/apktool

## NOTES / TRIPWIRES FOR NEXT SESSION
- Do not rerun `analyze_apk_surface` for parity without remembering it does
  NOT run androguard/APK zip inventory; compare only the surface sections.
- The perf change preserves output by construction, but any new regex
  family added later must add its required-character gate and a parity
  test (the colon-free `[deadbeef]` case is the cautionary example).
- Prompt/data-contract mismatch is documentation + output contract, not a
  cosmetic wording issue: an active run would send the AI to missing files.
