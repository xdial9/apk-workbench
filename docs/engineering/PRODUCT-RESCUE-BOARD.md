# Product Rescue Board

**Purpose:** turn APK Workbench's existing analysis capabilities into one
verifiable, useful per-app result. This is a delivery board, not a proposal to
rewrite the scanner or add another detection catalog.

**Snapshot:** 2026-11-17, M0, M1, and M2 are complete on `main`. M3's real-run
validation has been exercised but is **blocked** by a JNI evidence mismatch.
Current full test suite: **383 passed**. The pre-existing untracked
`ai-memory/test.txt` remains untouched.

**Evidence boundary:** the configured external workspace contains a real
Simple Calculator v85 run (`b8e85b99-a5f9-496d-b3a4-e15cb1deca73`), but its
final report exposes a cross-APK JNI mapping inconsistency. The four bundles
are frozen and verify, but M3 is not accepted until that discrepancy and the
missing per-stage `status.json` outputs are resolved and the report is
regenerated.

## Bottom line

This is not currently just a TruffleHog wrapper. The repository contains a
surface scanner, DEX analysis, a stdlib ELF/JNI analyzer, cross-APK JNI
matching, typed evidence links, trace-chain generation, report generation, and
bundle freezing/verification. For example, the scanner writes `links.jsonl`,
`entry_points.jsonl`, and `trace_chains.jsonl` in
[`run_static_surface_analysis`](../../src/apkworkbench/analysis/apk_surface.py);
cross-APK JNI matching is wired through
[`cross_apk_native_jni_match`](../../src/apkworkbench/analysis/apk_surface.py);
and `verify-workspace` exists in the CLI
([main.py](../../src/apkworkbench/cli/main.py)).

M1 now refreshes secret links after the scan, distinguishes missing and
malformed output from a successful empty scan, and tests the resulting trace
in the normal stage order. M2 adds a native-focused report view with
per-library parse/load state, JNI mappings and unmapped reasons, symbol and
string counts, citations, and native-related traces
([final_run.py](../../src/apkworkbench/reporting/final_run.py)). The real-app
quality of those results remains unverified.

This board deliberately does **not** call reports, native analysis, or bundle
freezing nonexistent. Those features are present. It distinguishes “code
exists and tests pass” from “the normal workflow produces a traceable result a
user can inspect.”

## Product target

For one acquired app bundle, one normal workflow must produce:

1. A frozen, verifiable evidence bundle with honest per-stage status and
   coverage.
2. One JSON report that preserves the structured surface, DEX, native,
   TruffleHog, and trace evidence.
3. One HTML report that makes the important results findable without requiring
   the reader to inspect raw JSON first.
4. Evidence citations and explicit unresolved/unmapped states; no inferred
   relationship presented as a proven link.

The tool is a static analyzer. It must not claim runtime behavior, exploitability,
or server-side facts that static evidence cannot establish.

## Board rules

- Work one item at a time; each item has a narrowly scoped acceptance gate.
- Use an existing acquired APK or a safe fixture. Do not make a Google Play
  acquisition a prerequisite for validating report assembly.
- Do not run the full Spotify heavy case. Do not remove resource caps to make
  tests pass; preserve counting, sharding, and partial-coverage behavior.
- Do not add more detection rules until the report and evidence joins below
  work end to end.
- A mocked fixture is necessary but not sufficient for the real-app proof gate.
- Keep secrets out of ordinary HTML summaries; link to protected evidence or
  redact values according to the existing policy.

## Milestones

### M0 — Reconcile the project's current-state records — DONE

**Priority:** P0 · **Estimate:** S · **Depends on:** none

Completed 2026-11-17 against `main` at `5f7b465`. The memory files contained
contradictory point-in-time statuses: some called P8 queued or freeze and
`verify-workspace` unimplemented, while the repository-local briefing and
current code/tests showed freeze completion. These snapshots are now labeled
as history and the current statuses are reconciled to source and tests.

**Files**
- `ai-memory/scanner-plan.md`
- `ai-memory/todo.md`
- `ai-memory/INDEX.md`
- `ai-memory/native-plan.md`
- `ai-memory/appdev.txt`
- `oc-handoff/99-briefing.md`

**Acceptance**
- Each file has a clearly dated “current state” and does not contradict the
  current `main` implementation.
- P0-P7, freeze/verification, cross-APK JNI matching, and trace-chain work are
  marked according to code and tests—not memory alone.
- Remaining defects are rechecked against current code before being called
  open or closed.
- No source code changes are included in this documentation synchronization.

**Updated:** `ai-memory/scanner-plan.md`, `ai-memory/todo.md`,
`ai-memory/INDEX.md`, `ai-memory/native-plan.md`, `ai-memory/appdev.txt`, and
`oc-handoff/99-briefing.md`. Historical snapshots remain labeled as history.
Full suite remained green: 381 passed in 5.71s.

### M1 — Join post-scan secrets into evidence links and trace chains

**Priority:** P0 · **Estimate:** M · **Depends on:** M0 ·
**Status:** DONE

This is the most direct bridge between the secret scanner and the rest of the
analysis. The initial surface pass no longer reads a possibly stale
TruffleHog file. After scanning, `analyze` rebuilds typed links, entry points,
trace chains, static output, and handoff files using the artifact's recorded
scan status. A successful empty scan is represented as `success` with
`finding_count: 0`; failed, missing/malformed, not-run, and running scans have
distinct linkage statuses and do not reuse old secret edges. The refresh runs
before reporting and the pipeline's evidence freeze. Existing frozen bundles
are left unchanged and surfaced as an explicit refresh failure instead of
being written through their read-only evidence contract.

The integration test proves one mapped and one unmapped finding, the complete
entry-point-to-method-to-secret trace for the mapped result, zero findings,
not-run, failed scan, and missing findings output. Focused link/pipeline tests
passed (13); the full suite passed (381).

**Likely files**
- `src/apkworkbench/cli/main.py` — stage ordering and post-scan integration
- `src/apkworkbench/analysis/surface/links.py` — existing typed edge builders
  and trace-chain writer; reuse rather than duplicate
- `src/apkworkbench/analysis/apk_surface.py` — current link write path and
  artifact locations
- `tests/test_surface_links.py`
- `tests/test_pipeline_integration.py`

**Acceptance**
- A pipeline fixture containing a TruffleHog result produces the expected
  evidence-backed secret edges after the secret stage.
- `trace_chains.jsonl` reflects those edges and contains a complete chain only
  when every hop is supported by evidence.
- Missing/failed TruffleHog input is represented explicitly; it is not
  converted to an empty result that implies “no secrets.”
- The post-scan update preserves the frozen bundle contract: either all
  intended data is assembled before freeze, or the workflow has a deliberate,
  tested lifecycle for updating and re-freezing.
- Tests cover mapped, unmapped, no-findings, and failed/missing scan cases.

All acceptance criteria are met by the post-scan refresh path and
`tests/test_pipeline_integration.py`.

### M2 — Make native analysis visible and useful in the final report

**Priority:** P0 · **Estimate:** M · **Depends on:** M1
**Status:** DONE

The native analyzer already emits structured library, symbol, JNI, load-site,
string, and coverage data. The final report now has per-artifact HTML tables
for library parse state and reasons, exports/imports, JNI mappings, load-site
state, string totals and coverage, unresolved JNI/dynamic registration, and
native-related trace citations. The JSON report retains the original
`static_analysis` records and adds filtered native links and trace chains.
Empty, failed, and not-run states are explicit. No native risk score was
introduced, and the new summary does not render secret values.

**Likely files**
- `src/apkworkbench/reporting/final_run.py`
- `src/apkworkbench/analysis/surface/native.py`
- `src/apkworkbench/analysis/surface/links.py`
- `tests/test_final_run_report.py`
- `tests/test_pipeline_integration.py`

**Report content**
- Native-library inventory and parse state, including libraries skipped or
  rejected with reasons.
- Exports: total, mapped to Java, unmapped with reason; imports and load-site
  state where present.
- Native string totals/emitted/sharded/partial coverage, not just displayed
  strings.
- JNI and secret trace chains with citations to the DEX/Smali location and
  native byte offset where those relationships are proven.
- A concise unresolved section: unmapped JNI, dynamic registration candidates,
  missing load site, or absent native libraries.

**Acceptance**
- HTML exposes these sections without requiring expansion of the entire raw
  evidence JSON.
- JSON retains complete machine-readable source records and coverage.
- Empty results say whether there were no native libraries, analysis failed,
  or a stage was not run.
- Secret values are not newly disclosed in summary text.
- A fixture proves a mapped JNI path and a separate unmapped-with-reason path.

All acceptance criteria are exercised by
`tests/test_final_run_report.py`; the full suite passes 383 tests.

### M3 — Produce and inspect one complete bundle from start to report

**Priority:** P0 · **Estimate:** M · **Depends on:** M1 and M2

**Status: IN PROGRESS — real-run validation found an acceptance blocker.**

**Run evidence (2026-11-17):**
- Real input: Simple Calculator v85, Google Play run
  `b8e85b99-a5f9-496d-b3a4-e15cb1deca73`; 4 APK components, independently
  verified; 32,997,496 bytes total.
- Existing successful Apktool and TruffleHog results were reused rather than
  rescanned. Post-scan refresh completed for all 4 components. The final JSON
  retains 13 unverified TruffleHog findings and reports 0 verified findings.
- Surface analysis accounted for 4 components: 1 success, 3 partial, 0 failed;
  2,074 static indicators. Reconciliation accounted for 4/4: 1 `complete`,
  3 `complete_with_warnings`. The CLI exits nonzero for the warning outcomes;
  it does not report an unaccounted component.
- Reports were regenerated:
  `workspace/reports/runs/b8e85b99-a5f9-496d-b3a4-e15cb1deca73/final-report.json`
  and `final-report.html`. They contain 471 endpoint candidates, 15 routes,
  2,160 Smali API call sites, 8,339 external DEX method references, 3,786 DEX
  API/config strings, 28 permission/API groups, and 201 rate-limit/retry clues.
  Their sizes are about 758 MB JSON and 1.13 GB HTML.
- The native split has 3 ELF libraries and 7 JNI exports. The generated report
  says 7 mapped and 7 unmapped (total 7), while that component's JNI inventory
  has 0 mapped entries and 7 unmapped entries. The run-level consistency flag
  is false. `cross_apk_native_jni_match` appends mapped facts and increments
  the mapped metric without reconciling the inventory/unmapped records. This
  is a verified source/report inconsistency; do not claim JNI mapping coverage
  is complete.
- No stage `status.json` files were found in the four component bundles (stage
  status is present in the processing database and final report instead).
- All 4 component bundles were frozen after report generation;
  `verify-workspace` passed for each with 0 mismatches, missing files, or extra
  files. Keep these bundles immutable while fixing the writer; validate any
  rerun in a new output workspace/run.

Run one small, representative app through the normal workflow. Prefer a
previously acquired local APK bundle. If none is available, use an operator-
approved sample; do not silently substitute a synthetic fixture for real-app
validation. Avoid a large corpus.

**Likely files if defects are found**
- `scripts/full_google_play_pipeline.sh`
- `src/apkworkbench/cli/main.py`
- `src/apkworkbench/database/workspace.py`
- `src/apkworkbench/reporting/final_run.py`
- `docs/reliability-and-recovery.md`
- `tests/test_pipeline_integration.py`

**Acceptance**
- Record the exact run ID, app/component counts, per-stage status, testable
  output paths, and reconciliation totals.
- Confirm final JSON and HTML are written and linked from the run summary.
- Confirm native records, DEX links, TruffleHog results, and trace chains agree
  with their source artifacts.
- Run `apkworkbench verify-workspace <bundle>` and capture a passing result.
- Any unsupported or absent data is reported as partial/not-applicable/skipped
  with a reason; no successful-looking empty fallback.
- Save a small, sanitized test fixture or reproducible test inputs only when
  licensing and data sensitivity permit. Do not commit APKs, credentials, or
  raw secrets.

**Known boundary:** no representative result bundle was found in the repository
tree. The external workspace was inspected as described above; M3 remains
open until the JNI inventory mismatch and per-stage status output are fixed and
the current-code report passes the acceptance checks.

### M4 — Re-audit determinism, unresolved scanner defects, and scale behavior

**Priority:** P1 · **Estimate:** M/L · **Depends on:** M3

The defect ledger in `ai-memory/scanner-plan.md` includes older open items
(such as D5, D6, D19, D20, and D21). Some may have been addressed by newer
commits or may need narrower definitions. Reproduce each against the current
`main` before changing code.

**Candidate checks**
- DEX string origin and ordering across multiple DEX files.
- ELF dynamic symbols when section headers/symbol tables are missing.
- Deterministic output under different `PYTHONHASHSEED` values for graph,
  call-site, and trace-chain outputs.
- Asset-to-reader links: only emit when code evidence proves the relationship;
  otherwise record not-applicable/unresolved with a reason.
- Resume after interruption: checkpoint validity, idempotent output, and no
  stale “running” marker after terminal failure.
- Large-output behavior: verify counts, shards/indexes, and partial coverage
  without loading unbounded artifacts into memory.

**Likely files**
- `src/apkworkbench/analysis/androguard_dex.py`
- `src/apkworkbench/analysis/surface/native_elf.py`
- `src/apkworkbench/analysis/surface/links.py`
- `src/apkworkbench/analysis/surface/checkpoint.py`
- `src/apkworkbench/analysis/apk_surface.py`
- targeted tests under `tests/`

**Acceptance**
- Every candidate is marked fixed, reproducibly open, or not applicable with
  a fixture/test or an explicit reason.
- No broad rewrite or cap deletion.
- Performance claims are measured on a named input and include elapsed time,
  peak memory if available, processed counts, and coverage.

### M5 — Define a release gate and narrow the product promise

**Priority:** P1 · **Estimate:** S/M · **Depends on:** M3

Document what the program does and does not prove, and make the user-facing
commands/report match that contract.

**Likely files**
- `README.md`
- `docs/commands.md`
- `docs/reliability-and-recovery.md`
- `docs/rules.md`
- `pyproject.toml` only if a release/CI gate needs configuration

**Acceptance**
- README points to the exact final JSON/HTML/bundle outputs and verification
  command.
- The report distinguishes static leads, verified secret findings, unverified
  leads, and incomplete coverage.
- A release candidate requires full tests, lint, one end-to-end bundle, clean
  reconciliation, and successful workspace verification.
- No claim of runtime proof, complete behavioral reconstruction, or universal
  coverage.

## Immediate next ticket

Finish **M3**: make cross-APK JNI mappings consistent across facts, metrics,
inventories, and report sections; emit per-stage `status.json` outputs; then
validate the corrected behavior in a new output workspace and freeze/verify
the resulting bundles. Do not start M4 until this real-run gate passes.

Do not begin with more detection rules, a broad architecture rewrite, a
large-scale acquisition, or a new reporting framework.

## What to stop doing for now

- Stop adding detection rules until M1-M3 produce and validate an end-to-end
  report.
- Stop treating a passing unit suite as proof of real-run output quality.
- Stop describing completed freeze/verification work as still unimplemented.
- Stop calling the whole program a TruffleHog wrapper without distinguishing
  the existing analyzer capabilities from the still-unproven user-facing
  integration.
- Stop making roadmap completion claims without a current test or artifact as
  evidence.

## Evidence references

- Bundle freeze and verifier implementation: `src/apkworkbench/database/workspace.py`
  (`freeze_evidence`, `verify_workspace`); CLI command:
  `src/apkworkbench/cli/main.py` (`verify_workspace`); tests:
  `tests/test_workspace_freeze.py`.
- Native facts and ELF/JNI analysis:
  `src/apkworkbench/analysis/surface/native.py`,
  `src/apkworkbench/analysis/surface/native_elf.py`,
  `tests/test_native_analysis.py`.
- Typed links and secret-edge builders:
  `src/apkworkbench/analysis/surface/links.py`,
  `tests/test_surface_links.py`.
- Final report assembly and HTML:
  `src/apkworkbench/reporting/final_run.py`,
  `tests/test_final_run_report.py`.
- Current end-to-end fixture pipeline:
  `tests/test_pipeline_integration.py`.
- Current full test baseline: `.venv/bin/python -m pytest -q` — **381 passed
  in 5.71s** on 2026-11-17.
