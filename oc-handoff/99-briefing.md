# APK Workbench — Current Engineering Brief

**Verified:** 2026-11-17
**Repository:** `main`, starting snapshot `5f7b465`
**Tests:** `.venv/bin/python -m pytest -q` — 381 passed in 5.71s
**Next work:** `docs/engineering/PRODUCT-RESCUE-BOARD.md`

## Current state

- Scanner phases P0-P7 are implemented.
- Bundle-level static-analysis relocation, `handoff.json`, `hashes.sha256`,
  evidence read-only permissions, and `verify-workspace` are implemented and
  have fixture/integration coverage.
- Native ELF/JNI analysis, embedded code/native extraction, cross-APK JNI
  matching, typed evidence links, and trace-chain generation are present.
- Commit `5f7b465` passes retained TruffleHog findings into
  `build_link_graph`. This is implementation evidence, not proof that all
  post-scan failure modes are safe: parse/load errors currently fall back to
  no findings, and the complete pipeline join still needs targeted tests.
- P8 is partial: no model dry-run, enforced AI output contract, location-map
  volume hierarchy, or split-component bundle aggregation has been
  demonstrated.
- No representative result bundle was found in the repository. The external
  configured workspace was not inspected; real-app report quality is
  unverified.

## What this phase updates

M0 in the product rescue board reconciles current-state notes against source,
tests, and recent commits. The old branch/test snapshots and Unit 1 design
remain in memory files as dated historical records; they must not be used as
the current work queue. No source code changes are part of M0.

## Rescue sequence

1. **M0 — current-state reconciliation:** update scanner, native, index,
   appdev, todo, and this briefing. Commit together.
2. **M1 — post-scan secret links:** add explicit status/error handling and
   pipeline tests for mapped, unmapped, absent, malformed, and failed
   TruffleHog inputs; ensure trace chains are generated from the final links.
3. **M2 — native report visibility:** present per-library parse/load/JNI
   status, totals, unmapped reasons, citations, and trace chains in the HTML
   report while preserving complete JSON evidence and avoiding secret leakage.
4. **M3 — one real-app end-to-end proof:** produce and inspect a small
   representative bundle, report, reconciliation, and workspace verification.
   Do not substitute fixture-only success for this proof.
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
