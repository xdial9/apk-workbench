![APK WORKBENCH](assets/apk-workbench-banner.svg)

# CLI Command Reference

**DISCOVER · DOWNLOAD · DECOMPILE · ANALYZE · CATALOGUE**

Run commands with the project virtual environment active:

~~~bash
source .venv/bin/activate
apkworkbench --help
~~~

## Command map

| Command | Function |
|---|---|
| **doctor** | Validate required external tools |
| **discover** | Authenticate and inspect F-Droid index records |
| **download** | Select, manifest, download, and verify new APKs |
| **decompile** | Run JADX and Apktool sequentially |
| **analyze** | Scan completed decompilations with TruffleHog |
| **report** | Generate sanitized JSON, HTML, and aggregate CSV reports |
| **status** | Summarize workspace processing state |
| **run** | Execute a new acquisition batch through reporting |
| **version** | Print the installed version |

---

## 01 · doctor

~~~bash
apkworkbench doctor
~~~

Checks that all required executables can be found and their version commands succeed. Required: **gpg**, **java**, **jadx**, **apktool**, and **trufflehog**. A missing or unhealthy required dependency produces a non-zero exit.

## 02 · discover

Authenticate the configured F-Droid index and display the latest indexed version for each package.

~~~bash
apkworkbench discover
apkworkbench discover --limit 50
apkworkbench discover --package org.example.app
apkworkbench discover --package org.example.app --limit 5
apkworkbench discover --refresh-index
~~~

| Option | Default | Meaning |
|---|---:|---|
| **--limit INTEGER** | 20 | Maximum package records displayed; 0 displays none |
| **--refresh-index** | off | Bypass local cache and retrieve a fresh signed index |
| **--package TEXT** | — | Exact Android application ID filter |

The authenticated index and detached signature are cached for six hours by default. The signature is re-verified on every cache hit. Discovery does not download APK files. Success reports the signer fingerprint, index digest, record counts, and **Index signature: VERIFIED**.

## 03 · download

~~~bash
apkworkbench download
apkworkbench download --apk-count 3
apkworkbench download --apk-count 5 --package org.example.app
apkworkbench download --apk-count 10 --refresh-index
~~~

| Option | Default | Meaning |
|---|---:|---|
| **--apk-count INTEGER** | 10 | Number of new unique APK binaries to select; minimum 1 |
| **--refresh-index** | off | Bypass local cache and retrieve a fresh signed index |
| **--package TEXT** | — | Restrict selection to one exact package ID |

Previously acquired SHA-256 hashes and duplicates in the current selection are excluded. A frozen manifest is atomically published before downloads begin. It records selection order, package/version identity, expected size and digest, source URL, and authenticated index digest.

The command prints its **Run ID** and **Frozen manifest** path. Save the UUID if you will run processing stages separately.

A shortfall is reported when fewer new unique binaries are available than requested. Any available selected artifacts are still processed.

## 04 · decompile

JADX runs first; Apktool runs second. Each APK is re-hashed and size-checked before either tool receives it. Each tool's successful output is tracked and resumed independently.

~~~bash
apkworkbench decompile
apkworkbench decompile --limit 5
apkworkbench decompile --run-id YOUR-RUN-ID
apkworkbench decompile --run-id YOUR-RUN-ID --force
~~~

| Option | Default | Meaning |
|---|---:|---|
| **--limit INTEGER** | 0 | Maximum eligible APKs processed; 0 means all in scope |
| **--force** | off | Re-run both decompilers, even when valid prior outputs exist |
| **--run-id TEXT** | — | Restrict processing to the frozen manifest and downloads from that run |

**Processing scope**

- Without **--run-id**, standalone decompilation considers eligible downloads across the workspace.
- With **--run-id**, only successfully acquired artifacts in that manifest are considered.
- The **run** command automatically passes its manifest ID to this stage.
- Failed or absent downloads are skipped; they are not replaced by older workspace APKs.

JADX and Apktool have separate output directories and logs. A retry skips a tool whose status is successful and whose output directory still contains files; it runs only the missing or unsuccessful tool. A successful result from one tool is not deleted or repeated just because the other tool failed. Each new attempt writes to a unique temporary sibling directory, validates that the tool produced files, and only then publishes the replacement. A failed or empty-output attempt leaves the previous published output intact. A failed forced refresh also retains the previous successful status/output, while the command reports the failed refresh for attention.\n\nThe **--force** option intentionally attempts both tools again. It does not delete published outputs up front: each replacement is staged and the old directory is kept until the replacement has passed validation. See [Retry-safe decompilation](retry-safe-decompilation.md) for the lifecycle, recovery behavior, and regression coverage.

## 05 · analyze

Run a local TruffleHog filesystem scan over JADX and Apktool output for successfully decompiled APKs.

~~~bash
apkworkbench analyze
apkworkbench analyze --limit 5
apkworkbench analyze --run-id YOUR-RUN-ID
apkworkbench analyze --run-id YOUR-RUN-ID --force
~~~

| Option | Default | Meaning |
|---|---:|---|
| **--limit INTEGER** | 0 | Maximum eligible APKs scanned; 0 means all in scope |
| **--force** | off | Repeat scans that previously succeeded |
| **--run-id TEXT** | — | Restrict analysis to the matching acquisition manifest |

Credential verification is disabled. The application checks that the installed TruffleHog filesystem command advertises the required safe-operation flags and fails closed if compatibility cannot be established.

Findings are unverified candidate indicators for manual review. They do not prove that a credential is active, valid, or exploitable. Raw/decoded secret values are not persisted in reports.

## 06 · report

~~~bash
apkworkbench report
~~~

Generates per-artifact sanitized JSON and HTML reports plus the aggregate **findings.csv**. This is a workspace catalogue operation and refreshes reports across the workspace.

## 07 · status

~~~bash
apkworkbench status
~~~

Displays workspace-wide totals for acquired binaries, successful JADX outputs, successful Apktool outputs, complete decompilations, successful scans, and failures.

## 08 · run

Execute a new acquisition batch and automatically scope decompilation and analysis to the manifest created by that batch.

~~~bash
apkworkbench run
apkworkbench run --apk-count 3
apkworkbench run --apk-count 10 --package org.example.app
apkworkbench run --apk-count 25
apkworkbench run --apk-count 10 --force-decompile --force-analyze
apkworkbench run --apk-count 10 --refresh-index
~~~

| Option | Default | Meaning |
|---|---:|---|
| **--apk-count INTEGER** | 10 | New unique APK binaries to select; minimum 1 |
| **--package TEXT** | — | Exact package ID filter for acquisition |
| **--force-decompile** | off | Repeat successful decompilation for this batch |
| **--refresh-index** | off | Bypass local cache and retrieve a fresh signed index |
| **--force-analyze** | off | Repeat successful scans for this batch |

Pipeline stages:

1. Authenticated F-Droid index retrieval.
2. Selection and immutable run-manifest publication.
3. Sequential downloads and integrity verification.
4. Manifest-scoped JADX and Apktool decompilation.
5. Manifest-scoped TruffleHog analysis.
6. Workspace report generation.

If no manifest is published, decompilation and analysis are skipped rather than falling back to workspace-wide processing. When a stage reports a non-zero exit, later stages continue for eligible artifacts; the overall command exits non-zero if attention is required.

## Exit statuses

| Code | Meaning |
|---:|---|
| **0** | Command completed without a reported error |
| **1** | Command failed or one or more pipeline stages need attention |
| **2** | Fewer new unique artifacts were available than requested |

## Common workflows

### End-to-end new batch

~~~bash
apkworkbench doctor
apkworkbench discover --limit 20
apkworkbench run --apk-count 10
apkworkbench status
~~~

### Separate acquisition and processing

~~~bash
apkworkbench download --apk-count 5
# Copy the Run ID printed by download.

apkworkbench decompile --run-id YOUR-RUN-ID
apkworkbench analyze --run-id YOUR-RUN-ID
apkworkbench report
apkworkbench status
~~~

### Intentional workspace-wide backlog processing

~~~bash
apkworkbench decompile
apkworkbench analyze
apkworkbench report
~~~

Use this workflow only when processing the entire eligible workspace is intentional.

### Troubleshooting

~~~bash
apkworkbench status
tail -n 120 "$HOME/APK-Workbench/logs/apkworkbench.log"

find "$HOME/APK-Workbench/results" \
  -type f \( -name 'jadx.log' -o -name 'apktool.log' \) \
  -print
~~~

See [Configuration](configuration.md) for workspace paths and timeouts.
