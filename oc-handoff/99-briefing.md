# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-17
**Repository:** `main`; M0 and M1 are complete in the current change
**Tests:** `.venv/bin/python -m pytest -q` — 381 passed
**Next work:** M2 on `docs/engineering/PRODUCT-RESCUE-BOARD.md`, only after
the user requests the next item

## Current state

- Scanner phases P0-P7 are implemented; P8 remains partial.
- Bundle-level static-analysis output, handoff, evidence freeze, and
  `verify-workspace` are implemented and fixture-tested.
- Native ELF/JNI analysis, cross-APK JNI matching, typed evidence links, and
  trace-chain generation are present.
- M1 now rebuilds links, trace chains, static output, and handoff files after
  TruffleHog. Successful-empty, failed, missing/malformed, and not-run scan
  states are distinct; stale secret edges are not reused. Frozen bundles are
  not modified and are reported as requiring an unfrozen workspace.
- The focused integration/link tests pass (13); the full suite passes (381).
- No representative result bundle was found in the repository. The external
  configured workspace was not inspected; real-app report quality remains
  unverified.

## Rescue sequence

1. **M0 — current-state reconciliation:** complete and committed.
2. **M1 — post-scan secret links:** complete; pipeline fixture covers mapped,
   unmapped, empty, not-run, failed, and missing TruffleHog output.
3. **M2 — native report visibility:** next board item; do not begin without
   the user's next-step instruction.
4. **M3 — one real-app end-to-end proof:** still required; do not substitute
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
