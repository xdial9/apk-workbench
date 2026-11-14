# SESSION SCRATCH / PAUSE HANDOFF — 2026-11-14

Status: deliberately paused by user after S8 performance fix. Read INDEX.md
first; this file holds the hands-on details for resuming.

## DONE THIS SESSION
1. Profiled the live Spotify sweep (py-spy): API-client marker loop ~28%,
   dependency-marker lower/any loop ~15%, code-rule loop ~7% of CPU.
2. Optimized `surface/sweep.py` (commit 964ee09, tests 205 green):
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

## RUNNING NOW (optimized Spotify heavy case)
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

## NEXT WORK (in order)
1. **Handoff contract fix — the real blocker for a user active run.**
   prompts 0/1/2/3/6 reference `surface/facts.jsonl` and
   `surface/location_map.json`; neither is emitted. Facts are embedded in
   `static-analysis.json`; `workbook.location_ledger` is the index.
   Decision default: emit additive `facts.jsonl` + `location_map.json`
   next to static-analysis.json and map the current
   `results/<pkg>/<ver>/<digest>/` roots to the prompt folder names
   (plan v2 §5 already requires facts.jsonl). Fallback: rewrite prompts to
   the embedded keys (less stable).
2. **Phase A ceiling removal.** The 64MB androguard cap fired on a NORMAL
   Antennapod app (dex partial) — empirical proof. Remove caps/timeouts
   per plan.txt Phase A; keep heartbeats.
3. **Prompt-chain dry run** on one real artifact, then the first active
   user run.

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
