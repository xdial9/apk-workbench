# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-17
**Repository:** `main`; M0-M3 complete with warnings; M3 changes are pending
local commit
**Tests:** `.venv/bin/python -m pytest -q` — 385 passed
**Next:** stop at M3; M4 needs a separately selected scope

## Current state

- Scanner phases P0-P7 are implemented. P8 remains partial: model dry-run,
  output-contract enforcement, location-map volume hierarchy, and
  split-component aggregation remain unvalidated.
- M1 refreshes secret links and trace chains after TruffleHog while preserving
  successful-empty, failed, missing/malformed, and not-run states.
- M2 exposes native parse/load state, JNI mappings/unmapped reasons, symbols,
  strings, citations, and native-related traces in the final report.
- M3 used the real Simple Calculator v85 run
  `b8e85b99-a5f9-496d-b3a4-e15cb1deca73` (4 APK components). Acquired APKs,
  decoded trees, and successful TruffleHog outputs were reused; no download,
  decompile, or TruffleHog rescan was performed.
- Per-bundle status files cover download, verification, decompile, surface,
  and TruffleHog. Run-level status files cover discover, download,
  verification, decompile, surface, TruffleHog, report, reconciliation,
  freeze, and pipeline. Bundle statuses are included in the hash manifest and
  frozen read-only.
- In isolated workspace
  `/home/dial9/APK-Workbench/workspace-m3-postfix-real`, post-scan links were
  refreshed for all 4 components and the corrected matcher reconciled 7 JNI
  exports as 7 mapped / 0 unmapped. The final JSON/HTML report was regenerated.
  It contains 13 unverified and 0 verified TruffleHog findings.
- Reconciliation: 4/4 accounted for (1 complete, 3 complete-with-warnings).
  Surface: 1 success, 3 partial. The run-level pipeline status is partial,
  not silently green.
- All 4 copied bundles were frozen and `verify-workspace` passed for each with
  zero mismatches, missing files, or extras. The original frozen evidence
  remains untouched.
- Report size remains a scale constraint: about 758 MB JSON and 1.13 GB HTML.

## Rescue sequence

1. M0 — current-state reconciliation: complete.
2. M1 — post-scan secret links: complete.
3. M2 — native report visibility: complete.
4. M3 — real-app report, statuses, freeze, and verification: complete with
   warnings.
5. M4/M5 — not started. M4 should first decide how to address report size and
   then re-audit determinism and scale.

## Guardrails

- Do not mutate the original frozen Calculator bundles.
- Do not run the full Spotify heavy case or work in tmpfs.
- Do not remove caps to avoid truncation; count, shard, and report partial
  coverage.
- Keep secrets out of ordinary human-readable summaries.
- A green test suite proves fixture behavior, not runtime behavior.
- Preserve the unrelated untracked `ai-memory/test.txt`.
