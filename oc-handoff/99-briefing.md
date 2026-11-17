# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-17
**Repository:** `main`; M0, M1, and M2 are complete
**Tests:** `.venv/bin/python -m pytest -q` — 382 passed
**Next work:** M3 on `docs/engineering/PRODUCT-RESCUE-BOARD.md`

## Current state

- Scanner phases P0-P7 are implemented; P8 remains partial.
- Bundle-level static-analysis output, handoff, evidence freeze, and
  `verify-workspace` are implemented and fixture-tested.
- M1 rebuilds links, trace chains, static output, and handoff files after
  TruffleHog. Successful-empty, failed, missing/malformed, and not-run scan
  states are distinct; frozen bundles are not modified.
- M2 adds native per-library parse/load state, JNI mappings and unresolved
  reasons, export/import records, native string counts and coverage, and
  cited native-related links/traces to the final report. Secret values are
  not included in the new native summary.
- Focused final-report tests pass; the full suite passes (382).
- No representative result bundle was found in the repository. The external
  configured workspace was not inspected; real-app report quality remains
  unverified.

## Rescue sequence

1. **M0 — current-state reconciliation:** complete.
2. **M1 — post-scan secret links:** complete.
3. **M2 — native report visibility:** complete.
4. **M3 — one real-app end-to-end proof:** next; must not substitute
   fixture-only success for this proof.
5. **M4/M5 — re-audit determinism/scale and establish a release gate** only
   after the end-to-end evidence exists.

## Guardrails

- One work item at a time; update this file, `ai-memory/INDEX.md`, and the
  canonical phase file before committing.
- Do not push without explicit instruction.
- Do not run the full Spotify heavy case or work in tmpfs.
- Do not remove caps to avoid truncation; count, shard, and report partial
  coverage.
- Keep secrets out of ordinary human-readable summaries.
- A green test suite proves fixture behavior, not real-app product quality.
