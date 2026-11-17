# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-17
**Repository:** `main`; M0, M1, and M2 are complete; M3 validation is in
progress; JNI reconciliation is fixed/tested, but status JSON and a
post-fix full run remain
**Tests:** `.venv/bin/python -m pytest -q` — 384 passed
**Next work:** emit per-stage status files and validate in a new output
workspace; preserve the frozen Simple Calculator run

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
- M3 inspected real Google Play run
  `b8e85b99-a5f9-496d-b3a4-e15cb1deca73` (Simple Calculator v85): 4 APK
  components verified, report regenerated, all 4 evidence bundles frozen and
  `verify-workspace` passed. Reconciliation accounted for 4/4 (1 complete,
  3 complete-with-warnings). The report has 13 retained unverified
  TruffleHog findings and 0 verified findings.
- M3 is not accepted: native metrics report 7 mapped and 7 unmapped JNI
  exports out of 7, while the component inventory has 0 mapped and 7
  unmapped in the frozen pre-fix report. The fix now reconciles these outputs;
  it passed against a temporary staging copy of the real data (7 mapped, 0
  unmapped, native HTML section agrees). No per-stage `status.json` writer
  exists. The JSON report is about 758 MB and HTML about 1.13 GB.
- Do not mutate the frozen run. Add status outputs and generate/verify a new
  full run in a new output workspace. Focused changes also fixed streaming
  selection of native-only links and the missing-hash verifier CLI error;
  full suite: 384 passed.

## Rescue sequence

1. **M0 — current-state reconciliation:** complete.
2. **M1 — post-scan secret links:** complete.
3. **M2 — native report visibility:** complete.
4. **M3 — one real-app end-to-end proof:** in progress; the first real report
   exposed blockers and must be rerun after they are fixed.
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
