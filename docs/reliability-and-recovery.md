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

The Google Play adapter retries each bundle component up to three times
after its initial attempt. The delay is exponential, starting at
`sources.google_play.retry_backoff_seconds` and capped at 30 seconds. The
adapter currently retries all download exceptions rather than classifying
HTTP status codes, and it does not interpret `Retry-After`. The pinned
upstream downloader uses a 60-second HTTP request timeout, removes incomplete
`.part` files on failure, and verifies the component against Play's supplied
size and digest. APK Workbench then independently verifies each APK's SHA-256
before recording it. A failure to commit verified acquisition history is fatal
to the current batch; it is not treated as an ordinary APK download failure.

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


## Google Play bundle acquisition

Google Play deliveries may contain `base.apk`, multiple `split_*.apk` files, and OBB expansion files. The acquisition adapter retains the complete delivery directory and writes `google-play-bundle.json` with component names, sizes, local SHA-256 digests, Play-hash verification status, package/version metadata, and signing-certificate digests. Every APK component is recorded separately in the acquisition history and run manifest so each is independently re-hashed before JADX/Apktool and TruffleHog. OBBs are retained and integrity-checked but are not passed to APK decompilers.

The Play client is an unofficial client for Google's internal Play API. Use a dedicated research Google account. The account token remains in the upstream client's private local configuration directory and must never be copied into the workbench, committed, or shared.


## Scaling to 15,000 apps

Use `scripts/acquire_15000_google_play.sh` after authentication and discovery. It executes 150 sequential runs of 100 apps, with a short pause between batches. Each batch gets its own immutable run manifest, so delivery metadata is resolved and frozen only for the next 100 apps rather than holding 15,000 Play delivery responses in memory.

The helper stops at the first failed or incomplete batch. Re-running it skips packages already recorded as Google Play acquisitions and continues with remaining catalog entries. If acquisition completed but decompilation or analysis failed, inspect the run ID printed by the CLI and retry that specific stage with `--run-id`; acquisition history intentionally prevents the batch helper from downloading that package again.

The CSV column historically named `index_sha256` is retained for workspace compatibility; in this source model it contains a digest of the frozen Google Play delivery metadata, not a repository index. The `google-play://` values in `download_url` fields are stable provenance identifiers, not fetchable CDN URLs; expiring Play delivery URLs are never persisted.
