# Reliability and Recovery

## Workspace serialization

Workspace database reads and mutations use an interprocess file lock at
`database/.workspace.lock`. The CLI holds the same re-entrant lock for each
workspace-mutating command and for the complete `run` pipeline. This prevents
two CLI processes from interleaving acquisition, decompilation, analysis, or
report publication against one workspace.

The lock is advisory. Do not edit workspace CSV files manually while a run is
active.

## Decompilation

JADX and Apktool are launched in separate process groups. Their combined output
is streamed to per-artifact log files under:

`results/<package>/<version>/<sha256>/`

- `jadx.log`
- `apktool.log`

A timeout or shutdown signal terminates the process group. Output is written to
staging directories and published only after the tool exits successfully and
produces usable files. A failed forced refresh leaves the previous successful
output in place.

## Acquisition retries

The downloader retries bounded transient connection failures and retryable HTTP
responses (408, 425, 429, 500, 502, 503, and 504). It honors numeric or HTTP-date
`Retry-After` values, capped at 60 seconds, and otherwise uses exponential
backoff. A failure to commit verified acquisition history is fatal to the
current batch; it is not treated as an ordinary APK download failure.

## Per-run accounting

Each `run` invocation freezes its selected artifacts in
`database/run_manifests/run_<run-id>.csv`. At pipeline completion, the
manifest is reconciled against immutable acquisition history, attempt records,
and processing status. The pipeline returns a nonzero exit status if any item
is not complete.

Inspect a run at any time with:

```bash
apkworkbench reconcile --run-id <run-id>
```

Possible outcomes include:

- `complete`
- `download_failed`
- `history_commit_failed`
- `history_missing`
- `acquisition_unaccounted`
- `acquisition_conflict`
- `pending_decompilation`
- `decompilation_failed`
- `interrupted_or_running`
- `awaiting_analysis`
- `analysis_failed`

## Resuming processing

The decompilation and analysis commands accept the original `--run-id` and
operate only on artifacts in that frozen manifest:

```bash
apkworkbench decompile --run-id <run-id>
apkworkbench analyze --run-id <run-id>
apkworkbench report
apkworkbench reconcile --run-id <run-id>
```

A stale `running` status is not treated as success. The corresponding stage
is retried when invoked again. Acquisition rows that were never committed are
reported as unresolved; the current CLI does not silently rewrite an old
manifest or claim that such an item was downloaded.

## Verification boundary

The automated test suite includes a local end-to-end test that launches real
subprocesses using synthetic JADX, Apktool, and TruffleHog executables, then
generates a report and reconciles the manifest. This verifies subprocess
wiring and stage integration without external network access or real Android
tool binaries.

A representative real APK batch and a sustained overnight soak test are still
required before treating the toolchain as production-validated.
