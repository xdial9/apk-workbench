# Product Rescue Board

**Purpose:** turn APK Workbench's existing analysis capabilities into one
verifiable, useful per-app result. This is a delivery board, not a proposal to
rewrite the scanner or add another detection catalog.

**Snapshot:** 2026-11-17, `main` at `5f7b465`. Current full test suite:
**381 passed in 5.71s**. M0 documentation synchronization is complete in this
change; the pre-existing untracked `ai-memory/test.txt` remains untouched.

**Evidence boundary:** no representative result bundle was found under the
repository root. The configured external workspace was not inspected, so real
APK output quality remains unverified. The test suite proves fixture behavior,
not the quality of a completed real-app report.

## Bottom line

This is not currently just a TruffleHog wrapper. The repository contains a
surface scanner, DEX analysis, a stdlib ELF/JNI analyzer, cross-APK JNI
matching, typed evidence links, trace-chain generation, report generation, and
bundle freezing/verification. For example, the scanner writes `links.jsonl`,
`entry_points.jsonl`, and `trace_chains.jsonl`
([apk_surface.py](../../src/apkworkbench/analysis/apk_surface.py), around
lines 1960-2005); cross-APK JNI matching is wired into the analysis run
(around lines 2090-2130); and `verify-workspace` exists in the CLI
([main.py](../../src/apkworkbench/cli/main.py), around line 685).

The user's experience is still understandable. The human-facing final report
shows DEX details, coverage, static indicators, and verified TruffleHog
findings, while its native summary is principally counts such as files and
mapped/unmapped JNI exports ([final_run.py](../../src/apkworkbench/reporting/final_run.py),
around lines 210-270 and 600-635). Commit `5f7b465` now loads retained
TruffleHog findings before calling `build_link_graph`; however, file/JSON
errors are treated as absent findings, and the normal pipeline still lacks an
assertion that the post-scan secret links appear in the final trace output
([links.py](../../src/apkworkbench/analysis/surface/links.py), around lines
680-735, 760-930, 960-1020). That failure handling and the resulting
human-readable native story are the first product gaps to prove or close.

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
**Status:** IMPLEMENTATION PRESENT; ACCEPTANCE OPEN

This is the most direct bridge between the secret scanner and the rest of the
analysis. The link builder accepts TruffleHog findings and contains
`native->secret`, `method->secret`, and `permission->secret` edge logic. The
surface analysis builds links and trace chains during its pass. Commit
`5f7b465` now loads `trufflehog/findings.json` before the link build and passes
those records to `build_link_graph`. This closes the missing-argument gap, but
does not yet meet this item's acceptance: file read/JSON errors are caught and
treated as absent findings, and there is no end-to-end assertion that the
normal post-TruffleHog run writes secret edges and matching trace chains.
Harden and test these semantics before marking M1 done.

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

### M2 — Make native analysis visible and useful in the final report

**Priority:** P0 · **Estimate:** M · **Depends on:** M1

The native analyzer already emits structured library, symbol, JNI, load-site,
string, and coverage data. The final JSON report includes each artifact's
`static_analysis` object and has aggregate native JNI counters, but the HTML
report does not currently present a native-focused per-library view. Make
existing evidence discoverable; do not invent a native “risk score.”

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

### M3 — Produce and inspect one complete bundle from start to report

**Priority:** P0 · **Estimate:** M · **Depends on:** M1 and M2

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
tree at this snapshot; an external configured workspace may contain one and
has not been checked.

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

M0 is complete. Start with **M1** before expanding scope. M1 is the shortest
path to answering the practical question:
does the pipeline combine its own app analysis with the secret-scan result to
produce useful, cited traces?

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
