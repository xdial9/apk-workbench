# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-17
**Repository:** `main`; fresh run completed, post-run mapping fixes tested
**Tests:** `.venv/bin/python -m pytest -q` — 401 passed;
`.venv/bin/ruff check .` — passed; focused Python compilation and
`git diff --check` — passed.
**Next:** reanalyze the fresh run in a separate writable workspace, regenerate
reports, freeze, and verify. See
[`FIRST-FULL-PIPELINE-PLAN.md`](../docs/engineering/FIRST-FULL-PIPELINE-PLAN.md).

## Current state

- Scanner phases P0-P7 are implemented. Current worktree closes the audited
  standalone-DEX and secret-to-method gaps; the frozen run still needs
  reanalysis before those fixes appear in its handoff. P8 remains partial:
  model dry-run, output-contract enforcement, location-map volume hierarchy,
  and split-component aggregation remain unvalidated.
- M1 refreshes secret links and trace chains after TruffleHog while preserving
  successful-empty, failed, missing/malformed, and not-run states.
- M2 exposes native parse/load state, JNI mappings/unmapped reasons, symbols,
  strings, citations, and native-related traces in the final report.
- M3 used the real Simple Calculator v85 run
  `b8e85b99-a5f9-496d-b3a4-e15cb1deca73` (4 APK components). Acquired APKs,
  decoded trees, and successful TruffleHog outputs were reused; no download,
  decompile, or TruffleHog rescan was performed.
- The three non-base split APKs contain no DEX payload. Androguard correctly
  reported `not_applicable`; the surface driver incorrectly downgraded that
  to partial. The driver now retains `not_applicable` DEX coverage without
  downgrading the overall surface result. Valid cached successful reuse also
  no longer makes the run status partial.
- All 4 components now have surface status `success`; DEX coverage is
  `success` for base and `not_applicable` for the three splits. Reconciliation
  is 4/4 `complete`; run-level surface, reconciliation, and pipeline statuses
  are `success`.
- In isolated workspace
  `/home/dial9/APK-Workbench/workspace-m3-postfix-real`, post-scan links were
  refreshed for all 4 components and the corrected matcher reconciled 7 JNI
  exports as 7 mapped / 0 unmapped. The final JSON/HTML report was regenerated.
  It contains 13 unverified and 0 verified TruffleHog findings.
- All 4 copied bundles were frozen and `verify-workspace` passed for each
  with zero mismatches, missing files, or extras. The original frozen evidence
  remains untouched.
- Report size remains a scale constraint: about 758 MB JSON and 1.13 GB HTML.
- Phase 4 cleared all 8 repository Ruff findings. Full suite at that gate:
  **392 passed**. Both pipeline shell syntax checks and `git diff --check`
  passed.
- Phase 5 used the previous Simple Calculator package identity,
  `com.simplemobiletools.calculator`, with anonymous auth in isolated
  workspace `/home/dial9/APK-Workbench/workspace-first-full-20261117`.
  Corrected file-only discovery skipped broad catalog requests and recorded
  exactly one package.
- Fresh run `fc75a20f-f08e-455c-a833-31806844280e` completed all stages:
  4 APK components acquired, verified, decoded, scanned, reconciled (4/4
  complete, zero warnings), frozen, and verified. Report sizes: JSON
  757,972,011 bytes; HTML 1,125,800,064 bytes. TruffleHog reported 13
  unverified and 0 verified candidates, with no failed scans. The subsequent
  mapping audit found two standalone asset DEX files omitted from DEX
  analysis and no proven Smali method-secret edges despite nonempty findings.
- Current code analyzes standalone DEX with bounded caps and explicit file
  ledger states. TruffleHog paths are root-confined; a secret maps only to
  the exact containing Smali method, and otherwise receives an explicit
  `usage_unverified` reason. The actual two Calculator asset DEX files parse
  successfully (2 files, 3,330 classes). The old frozen outputs were not
  modified; reanalysis in a separate writable copy is still required.
- A 12-layer branching call-graph test reproduced 4,096 equivalent trace
  paths. Trace output now retains one shortest cited path per reachable
  entry-point/secret pair; the link graph still preserves all call edges.
- The end-to-end pass found the runner overwrote standalone-DEX analysis with
  APK-only analysis. It now merges the models, metrics, and DEX indexes; the
  integration regression proves the asset class and call edge survive.
  Corrected copied-workspace reanalysis is running.
- Androguard output was unusually verbose (about 159 MB transcript in the
  fresh run); log-noise reduction remains an open scale task.

## Rescue sequence

1. M0 — current-state reconciliation: complete.
2. M1 — post-scan secret links: complete.
3. M2 — native report visibility: complete.
4. M3 — real-app report, statuses, freeze, and verification: complete.
5. First fresh-run readiness — pending; see
   `docs/engineering/FIRST-FULL-PIPELINE-PLAN.md`. The previous M3 work reused
   existing acquired APKs, decoded trees, and TruffleHog output, so it is not
   evidence of a fresh full pipeline run.
6. Expired-delivery retry fix — complete; regression was observed failing on
   the stale URL, then all 9 focused Google Play source tests passed. No live
   Play request was made.
7. Freeze dotfile hashing/verification — complete; regression failed before
   the fix. Recursive permissions and fail-closed chmod handling are complete;
   8 freeze tests pass and `ai_analysis/attempt-01` remains writable.
   Verification also rejects writable files, directories, and hash manifests.
   Combined phase tests: 22 passed; full suite: 391 passed. Next: restore
   Ruff/whitespace checks.

## Guardrails

- Do not mutate the original frozen Calculator bundles.
- Do not run the full Spotify heavy case or work in tmpfs.
- Do not remove caps to avoid truncation; count, shard, and report partial
  coverage.
- Keep secrets out of ordinary human-readable summaries.
- A green test suite proves fixture behavior, not runtime behavior.
- Preserve the unrelated untracked `ai-memory/test.txt`.
