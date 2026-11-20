# First Fresh Full-Pipeline Run — Operator and Engineering Guide

**Status:** The fresh run completed all pipeline stages and froze its bundles.
The Phase 7 evidence audit found DEX/secret-link mapping gaps. Source fixes
and regression tests now pass; the frozen run has not been rewritten, so
acceptance remains pending a separate reanalysis.
**Planning baseline:** 2026-11-17, repository `main` at `5afe633`.
**Goal:** complete and verify one fresh, small, operator-approved Google Play
app run through acquisition, verification, decompilation, static surface
analysis, TruffleHog, reporting, reconciliation, and evidence freeze.

This guide is the current step-by-step plan and execution record for the first
fresh full run. It supersedes the stale “current snapshot” and “immediate next
ticket” wording in older handoff notes. The run-level workflow completed, but
the evidence-mapping acceptance gate is not yet closed.

## 1. Verified starting point

- The working branch is `main` at `5afe633`. Local `agent-work` is 17 commits
  behind `main`, has no unique commits, and must not be used as the starting
  point for new work.
- The checkout has a pre-existing staged addition, `ai-memory/test.txt`.
  Preserve it; it is unrelated to this guide.
- `.venv/bin/python -m pytest -q`: **386 passed** (observed during the audit).
- After Phases 1-4, the full suite passes: **392 passed**.
- `.venv/bin/ruff check .`: **8 findings** (observed during the audit):
  two `EXE001`, two `TRY004`, two `ISC004`, one `F841`, and one `F601`.
- Phase 4 cleared all eight findings; the current Ruff check passes.
- `git diff --check agent-work..main` reported trailing whitespace in
  `src/apkworkbench/analysis/surface/links.py` at lines 747 and 776.
- With `.venv/bin` on `PATH`, `apkworkbench doctor` reported **READY** for
  required tools and resolved Play auth to **ANONYMOUS**. The anonymous
  dispenser is a documented external reliability risk. These results verify
  the current environment only; they do not prove a live Play request works.
- The Simple Calculator v85 evidence run is not a fresh full run: acquired
  APKs, decoded output, and successful TruffleHog output were reused. Its
  final report was about 758 MB JSON and 1.13 GB HTML.
- The fresh-run acceptance target is one app, not the Spotify heavy case or a
  batch acquisition.

## 2. Confirmed issues to close before live acceptance

1. **Expired Play delivery retry uses the stale file object/URL.** The retry
   creates a downloader from refreshed delivery metadata but looks up the
   file from the original delivery in
   `src/apkworkbench/sources/google_play.py`. An offline reproduction showed
   both attempts used `old-url`. The existing retry test does not distinguish
   the refreshed file.
2. **Freeze/verification disagree about dotfiles.** Freeze omits dotfiles from
   `hashes.sha256`, while verification treats unlisted files as extras. This
   is source-confirmed but was not runtime-reproduced during the audit.
3. **Nested evidence directories may remain writable after freeze.** Freeze
   changes the evidence roots and only immediate `apktool` children, not
   every nested directory. This is source-confirmed but was not
   runtime-reproduced during the audit. Ensure only the designated
   `ai_analysis/` area remains writable.
4. **Repository quality gate** (closed in Phase 4): the initial Ruff and
   worktree whitespace findings were resolved surgically and rechecked.
5. **Explicit package-file discovery started broad crawling.** A
   `--packages-file`-only command still queried the 52-category Play catalog
   before adding the supplied package IDs. The first request hit HTTP 429;
   it was stopped before any APK acquisition. Phase 5 now skips catalog
   crawling for file-only discovery and validates package IDs before network
   access.

The three freeze findings need focused regression tests before a fresh run is
used to claim freeze integrity. Do not silently downgrade them to “accepted
risk.”

## 3. Execution sequence and phase gates

Each numbered phase is a separate, bounded task. Stop after its gate passes;
do not combine fixes across phases. Re-read the current source before editing.

### Phase 0 — Align operator documentation (done in this update)

- Point installation instructions at the supported `main` branch rather than
  the stale `fix/apktool-only-trufflehog-pipeline` branch.
- Mark stale M3 status notes as historical and point active handoff material
  to this guide.

**Gate:** the README and installation guide clone `main`; active status notes
agree that M3 is complete, the suite has 386 tests, and no fresh full pipeline
run has yet been demonstrated.

### Phase 1 — Correct refreshed-delivery retry (complete)

- Change retry file lookup to use the refreshed delivery object, not the
  original plan delivery.
- Strengthen the focused test so original and refreshed deliveries expose
  different file objects/URLs; assert the retry fetches only the refreshed
  file.
- Keep retry count, exception behavior, and unrelated acquisition semantics
  unchanged.

**Gate:** focused acquisition retry test passes and proves the refreshed URL
was used; relevant acquisition tests pass.

**Verified:** the strengthened retry regression failed before the source fix
because it observed `old-url` instead of `fresh-url`. After the fix,
`.venv/bin/python -m pytest -q tests/test_google_play_source.py` passed all 9
tests, and Ruff passed for the two changed files. No live Play request was
made.

### Phase 2 — Make freeze hashing and verification agree (complete)

- Define one consistent set of frozen regular evidence files for both hash
  creation and verification. Include ordinary hidden/dotfiles; do not make
  symlinks or files outside the frozen evidence scope part of the evidence by
  accident.
- Add a regression fixture with a dotfile, freeze it, and verify it without
  an “extra” or missing-file result.
- Preserve the explicitly writable AI-analysis area according to the
  repository's bundle contract.

**Gate:** dotfile fixture passes freeze and verification; existing freeze
tests remain green.

**Verified:** the new nested-dotfile regression failed before the source fix
because `surface/.analysis-metadata` was absent from `hashes.sha256`. Freeze
now hashes regular dotfiles along with other evidence files, and verification
passes with no mismatches, missing files, or extras. The full
`tests/test_workspace_freeze.py` module passed all 5 tests at the Phase 2
gate; after Phase 3, the expanded module passes all 6 tests. Ruff passed for
the changed source and test files. The explicit `ai_analysis/` and
`database/` exclusions remain unchanged.

### Phase 3 — Enforce read-only nested evidence directories (complete)

- Apply read-only directory permissions recursively within the evidence
  roots, while preserving the explicit writable AI-analysis area.
- Add a nested-directory fixture and assert the resulting permission bits.
  Avoid relying only on attempted writes when tests may run with elevated
  privileges.
- Re-run freeze verification tests to ensure the directory change does not
  alter hashing or the allowlisted writable area.

**Gate:** all nested evidence directories meet the documented permission
contract; AI-analysis remains writable; freeze and verification tests pass.

**Verified:** the nested-directory permission regression failed before the
source fix on a directory under `apktool/smali/`. An audit then found that
file chmod errors were swallowed and the verifier could still return `ok`.
Freeze now traverses declared evidence roots without following symlinks,
applies read-only modes to evidence files, directories, and the hash
manifest, and rolls back modes/removes the manifest if chmod fails.
`verify_workspace` reports writable evidence files, directories, and the
hash manifest and fails status accordingly; the CLI prints those paths.
Tests prove nested `apktool`, `surface`, and `stages` directories are
read-only, `ai_analysis/attempt-01` remains writable, injected chmod failure
does not leave a hash success marker, and verification/CLI reject writable
evidence. The full freeze module passes 8 tests; the combined freeze,
verifier CLI, pipeline integration, and Google Play acquisition run passes
22 tests. Ruff and `git diff --check` pass for the phase changes.

### Phase 4 — Restore the local quality gate

- Fix the current Ruff findings with minimal, behavior-preserving edits.
- Remove the branch-diff whitespace issues if still present in the current
  worktree; do not edit unrelated lines.
- Run the full test suite, Ruff, both pipeline shell syntax checks, and
  `git diff --check`.

**Gate:** all commands pass on `main`; report the exact full test count and
command output. Do not proceed on a known failing CI gate.

**Verified:** the initial 8 Ruff findings were corrected: the two shebang
scripts now have executable modes; malformed JSON object shapes raise
`TypeError`; report strings retain their output with explicit grouping; the
unused test assignment and duplicate fixture key were removed. Regression
tests cover both malformed surface object shapes. Full suite:
`.venv/bin/python -m pytest -q` — **392 passed in 6.30s**. Repository Ruff:
`.venv/bin/ruff check .` — **All checks passed!** Both
`bash -n scripts/full_google_play_pipeline.sh` and
`bash -n scripts/acquire_15000_google_play.sh` passed; `git diff --check`
passed.

### Phase 5 — Preflight one approved app

- Use a persistent on-disk workspace, not tmpfs. Check free disk before
  starting; the historical report alone was over 1 GB in HTML.
- Activate the project virtual environment and run `apkworkbench doctor`.
- Select a small, free, operator-approved Play package ID and a compatible
  device profile. Do not silently substitute an app or use the Spotify heavy
  case.
- Prefer configured account auth for reliability if available. If anonymous
  auth is used, record that choice and treat dispenser failure as an external
  blocker, not as scanner evidence.
- Confirm no existing workspace result will be mistaken for this fresh run.

**Gate:** doctor succeeds; exact package ID, auth mode, workspace path, and
available disk are recorded before acquisition.

**Verified:** with `.venv` activated, `apkworkbench doctor` reported READY
for `playstore-cli`, Java, Apktool, TruffleHog, and Androguard. Auth resolves
to ANONYMOUS; the dispenser's reliability warning remains. The previous real
run identifies the selected package as `com.simplemobiletools.calculator`;
under the user's request to execute this plan, that previously analyzed
package was reused as the least-surprising one-app target. Available disk was
653 GB. The fresh persistent workspace is
`/home/dial9/APK-Workbench/workspace-first-full-20261117`; the prior
3.0-GB evidence workspace was not modified.

### Phase 6 — Run the fresh end-to-end workflow

Make discovery explicit with a one-line package-ID file, then run that exact
package. When `--packages-file` is used without a query or category, discovery
uses only those package IDs and does not crawl the general Play catalog.

```bash
apkworkbench discover --packages-file <one-line-package-id-file> --limit 1
apkworkbench run --package <operator-approved-package-id>
```

The package file should contain only the operator-approved package ID, one
line, and should live outside the repository. The exact-package run is
intentional: it avoids selecting an unrelated entry from the rolling catalog.

The first attempt exposed that file-only discovery still crawled all Play
categories; after the fix, regression tests proved that the file-only path
does not call Google Play discovery. The initial attempt hit HTTP 429 on its
first category and was stopped before APK acquisition. The corrected
discovery completed at 2026-11-17 23:06:39-05:00 and catalogued exactly one
package.

Do not run only `analyze`, and do not reuse old decoded or TruffleHog output
for this acceptance run. Capture the command transcript, run ID, timestamps,
and any nonzero status. Do not install or execute the acquired APK.

**Gate:** a new immutable run manifest exists; acquisition and independent
verification completed; run-level discovery and report/reconciliation states
and per-component download/verify/decompile/surface/TruffleHog states are
explicit; final JSON and HTML report were generated; reconciliation accounts
for every manifest item.

**Completed:** fresh run
`fc75a20f-f08e-455c-a833-31806844280e` started at 2026-11-17 23:06:50-05:00
in the workspace above. Download and independent verification succeeded for
four APK components; Apktool completed for all four. Surface analysis is
complete for 36,867 text files (35,488 smali) in the base component. The
Androguard DEX worker completed; TruffleHog completed all 4 components with
13 unverified and 0 verified candidate findings, with no failed scans.
The report stage completed with JSON at 757,972,011 bytes and HTML at
1,125,800,064 bytes. Stage status files report success for download,
decompile, surface, TruffleHog, report, reconciliation, freeze, verification,
and pipeline; discover is `skipped` because the run consumed the saved
discovery catalog. Reconciliation is 4/4 complete with zero warnings;
freeze covered all 4 bundles with zero issues, and workspace verification
passed. The run transcript was about 159 MB, largely due to verbose
Androguard diagnostics.

### Phase 7 — Verify the evidence package

- Record component totals and per-stage status/coverage. Treat
  `not_applicable`, skipped, partial, and failed as distinct outcomes and
  include their reasons.
- Check that the final JSON/HTML paths are in the run report and measure their
  sizes; do not infer completeness from a successful CLI exit alone.
- Check that DEX, native/JNI, secret, link, and trace output counts agree with
  their source artifacts where applicable.
- Require reconciliation `complete == total`; if warnings or incomplete
  items remain, report them instead of calling the run complete.
- Run `apkworkbench verify-workspace <bundle>` for every frozen bundle and
  require zero mismatches, missing files, and extras.

**Gate:** a result record contains the exact run ID, approved package,
component counts, stage outcomes, reconciliation totals, report paths/sizes,
and verifier result for each bundle, and the post-run mapping audit closes
all recorded DEX and secret-link gaps.

**Audit result:** the command-level gates above passed, but the data-mapping
audit did not. The decoded base component contains
`apktool/assets/audience_network/classes.dex` (57,076 bytes) and
`classes2.dex` (5,237,600 bytes); the original surface ledger marked both as
`skipped_container` and the DEX model omitted them while claiming success.
The link graph also had 43 entry points and 852,498 links but an empty
`trace_chains.jsonl`; TruffleHog paths were absolute, so Smali method links
were not produced. `link_type_method_secret` nevertheless said `success`
with 13 findings and no per-finding mapping reasons.

The current source now analyzes standalone DEX with the existing bounded
file/byte budgets and records `analysed_dex` or a diagnosed `skipped_dex` in
the file ledger. Secret paths are normalized only when they resolve inside
the bundle's `apktool/` root; a finding maps to the one method containing its
reported Smali line, otherwise `secret_usage` records `usage_unverified` and
a reason. Secret edge coverage no longer reports success when findings exist
but no edge can be proven. Regression tests pass, including a real-payload
check against the two Calculator asset DEX files (2 DEX files, 3,330 class
entries, success coverage). These changes have **not** been applied to the
frozen run. A second audit found trace generation enumerated every simple
call path; a 12-layer branching graph produced 4,096 equivalent entry-point
to-secret traces. Trace output now uses breadth-first traversal to emit one
shortest cited path per reachable entry-point/secret pair, while the full link
graph retains all call edges. The next end-to-end pass exposed a pipeline
overwrite: `run_static_surface_analysis` replaced the surface pass's
standalone-DEX model with the APK-only model. The runner now merges both
models, metrics, and DEX indexes; an integration regression proves the asset
class and its call edge survive. That run also exposed a non-serializable
Androguard `MethodAnalysis` object in embedded-Dex permission records; these
now use the same JSON-safe method/call-site schema as APK DEX records, with a
serialization regression. The full suite passes 402 tests and Ruff. A
corrected reanalysis is running in the separate writable workspace.
Regenerate reports, freeze, and verify before calling Phase 7 accepted.

### Phase 8 — Evaluate AI handoff separately

The first fresh full pipeline run does not by itself close P8. Separately
validate the prompt/model dry-run, enforced AI output contract, location-map
volume hierarchy, and split-component bundle aggregation. Until those gates
pass, describe the output as a verifiable static-analysis bundle, not a fully
validated AI handoff.

## 4. Stop conditions

Stop and preserve evidence if the run has an acquisition/verification failure,
missing stage status, unexplained coverage gap, inconsistent counts,
incomplete reconciliation, report-generation failure, or failed workspace
verification. Do not rerun destructively over frozen evidence. Record the
exact failure and use a later, separately scoped fix task.

Do not commit APKs, Play credentials/tokens, or raw secret values. Do not push
without explicit instruction. The staged `ai-memory/test.txt` is pre-existing
and outside this plan.
