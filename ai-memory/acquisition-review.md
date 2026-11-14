# ACQUISITION STAGE REVIEW — enumeration/catalog/download (Phase 0 STARTER)
Created 2026-11-14 at the "start at the very beginning" re-work order.
Scope: discover -> download. Consumption map at the end (AI handoff impact).
Baseline: tests 152 green; branch feature/goopdl-account-auth.

================================================================================
FINDINGS (data-verified by code read; keep honest, no guesses)
================================================================================
F1. DISCOVERY PROVENANCE IS LOST (handoff-critical, fix now)
- google_play.py discover() collects apps by package_id dedupe; WHO brought
  the app (query text vs category id) is discarded. CLI catalog rows contain
  metadata only. Effect: for an acquired APK, neither the catalog nor the
  bundle manifest says WHY it was acquired — the terminal AI workchain lacks
  selection context (prompt 2's "provenance" section becomes inference).
FIX (implemented in this batch):
  - discover() tracks channels: pkg -> "query:<text>" / "category:<id>";
    on_batch callback now receives (apps, channels).
  - catalog CSV gains two columns: discovery_channel + discovery_time
    (RFC3339 UTC); _read_catalog tolerates legacy 5-col files.
  - download passes per-package provenance into GooglePlaySource.download()
    and google-play-bundle.json records it under "provenance" (+ workchain
    runtime context: analyzer/pipeline versions absent — added pipeline keys)
  - prompts: 0.txt location listing mentions provenance; README gaps updated.

F2. STALE DELIVERY BETWEEN inspect() AND download() (fix: refresh now, small)
- plan._delivery frozen at inspect; download() re-derives play_files from the
  SAME stale delivery (line ~327-336) and retries up to 3x with backoff.
- FIX (implemented): on download failure of an attempt, fetch a FRESH
  per-component delivery once (re-inspect co-located delivery refresh) —
  VERDICT: not in this batch; requires re-inspect plumbing (#; deferred to P2;
  recorded as P2-1 here). IMMEDIATE chance: when attempts exhaust, error says
  plan may be stale — message improvement only (implemented).

F3. PARTIAL/GARBAGE RERUN HYGIENE (fix: sweep leftover .part)
- download() writes directly in downloads/<pkg>-<ver>/; a killed run can
  leave *.part + partial ORB files. Rerun overwrites same names; leftover
  unknown names accumulate unchecked.
FIX (implemented): at bundle completion, remove *.part leftovers + record any
  UNMATCHED extra files in bundle metadata "extra_files" (never delete them —
  they might be pre-existing operator files; only .part from stay files are
  purged).

F4. DISCOVERY CHANNEL DETAIL IS VERBATIM TEXT TREATED AS IDENTITY
- F1 covers source-of-select; channel text is md-unsafe if huge? search
  queries are user-controlled, escaped via csv fields; fine.

F5. catalog union semantics CHANGE (intentional, tested): rows keep oldest
  seen channel; new discovery passes DO NOT overwrite existing channels
  (stability for provenance over time; reruns add only missing rows).

F6. NOT-a-defect but reads like one: _call() sleeps a random 2-5s before
  EVERY call — by doctrine (SLOW + rate damping) keep.
  P2 later: adaptive pacing per play-plan-v2 surface item A.

F7. VERIFY later when the whole per-run workchain exists:
- per-artifact provenance references RUN-scoped artifacts (phase-one report).
  They live run-scoped in database/run_manifests/reports (§8F moves them to
  runs/<run_id>/ in Phase C). Bundle provenance.json (added) references them
  by workspace-relative path so the AI can find them today.

================================================================================
HANDOFF CONSUMPTION MAP (what the final AI gets from acquisition now)
================================================================================
- downloads/<pkg>-<ver>/google-play-bundle.json: per-file hashes,
  sizes, kinds, signer set, provenance (channel, run, times), extra_files.
  => prompt 0/1/2 citation targets: "manifest/<file>".
- database/google_play_discovery.csv: channel/time per package.
- database/run_manifests/run_<id>.csv + reports/phase_one_verification_<id>
  .json: run-level; referenced from bundle provenance.json (written only
  when a run_id was attached; single --package acquires also attach run).

PROMPTS CROSS-CHECK after wiring: 0.txt (location list updated for
provenance.json; not moved), 1.txt unchanged (raw-first works w/o these),
2.txt reads provenance in the "provenance" step (mention added), 5.json
schema adds provenance passthrough fields into ai_analysis.json.

================================================================================
DECISION LOG (short, dated; details in commits)
2026-11-14 START acquisition rework at beginning per user order.
2026-11-14 Delivered: F1 provenance wiring (discover->catalog->bundle),
       F3 rerun hygiene, F2 partial message, handoff wiring v0.
DEFER: delivery staleness re-inspect (P2-1), pacing redesign (P2-2),
       Phase C run-folder layout (P2-3).
================================================================================
EOF_MARKER
