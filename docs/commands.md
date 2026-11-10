# CLI Command Reference

All discovery and acquisition commands use Google Play Store. No other source is configured or used.

## Authentication prerequisite

Run these once in the same virtual environment as APK Workbench:

```bash
playstore-cli login
playstore-cli checkin
```

Use a dedicated research Google account. The upstream client uses an unofficial Google Play API and may result in account restrictions.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Check Play client, Java, Apktool, and TruffleHog |
| `discover` | Collect package IDs from Google Play charts, categories, searches, or a package file |
| `download` | Freeze delivery hashes and download complete Play app bundles |
| `verify-downloads` | Independently re-hash and verify every file in a completed acquisition run |
| `decompile` | Decode acquired APK components with Apktool |
| `analyze` | Run TruffleHog locally and retain verified findings |
| `report` | Generate reports containing complete original finding objects |
| `status` | Summarize acquired APK components and processing state |
| `reconcile` | Account for every item in a frozen acquisition manifest |
| `run` | Execute acquisition, decompilation, analysis, reporting, and reconciliation |

## Discovery

```bash
apkworkbench discover --limit 15000
apkworkbench discover --query banking --query fintech --query wallet
apkworkbench discover --category FINANCE --category APPLICATION --limit 1000
apkworkbench discover --packages-file packages.txt --limit 15000
```

Options:
- `--query TEXT`: repeatable Google Play search query.
- `--category ID`: repeatable Google Play category ID.
- `--limit INTEGER`: maximum unique package IDs to save; default 15,000.
- `--per-category INTEGER`: top-free chart cap per category; default 200.
- `--per-query INTEGER`: search cap per query; default 516.
- `--packages-file PATH`: UTF-8 file with one package ID per line; blank lines and lines beginning with `#` are ignored.

The catalog is saved to `database/google_play_discovery.csv`. The requested limit is not a promise that Google Play will return that many unique apps.

## Acquisition

```bash
apkworkbench download --apk-count 100
apkworkbench download --package com.example.app
```

`--apk-count` is retained as the CLI option name for compatibility, but its value means the number of **apps**, not the number of APK split files. Each selected app can produce multiple manifest rows—one per APK component. OBBs are preserved in the bundle directory and recorded in its JSON bundle manifest.

The immutable run manifest is published only after Play delivery metadata and expected component hashes have been retrieved. It is published before downloading the first component. The current upstream client supports free apps; an app not yet in the research account library may be added to it during delivery acquisition.

## Processing

```bash
apkworkbench decompile --run-id RUN_ID
apkworkbench analyze --run-id RUN_ID
apkworkbench report
apkworkbench reconcile --run-id RUN_ID
```

Each APK component is independently re-hashed before Apktool decoding. TruffleHog selects verified results with `--results=verified`; findings not explicitly marked verified are rejected.

## Full Google Play pipeline

Activate the project environment, then run the end-to-end workflow:

```bash
source .venv/bin/activate
bash scripts/full_google_play_pipeline.sh
```

Defaults are one new free app, the Google Play Tools category, and the search query `file manager`. Set these environment variables to change the scope:

- `APKWORKBENCH_QUERY` (default: `file manager`)
- `APKWORKBENCH_CATEGORY` (default: `TOOLS`)
- `APKWORKBENCH_DISCOVERY_LIMIT` (default: `30`)
- `APKWORKBENCH_APP_COUNT` (default: `1`)

The runner executes these stages strictly in order:

1. Discover apps and save the package catalog.
2. Download complete APK bundles from Google Play.
3. Independently verify the immutable run manifest, APK/OBB files, file sizes, local SHA-256 values, Play-provided digests, and bundle identity.
4. Run Apktool to completion for every APK component in the run and persist decoded output.
5. Only after the Apktool stage returns successfully, run TruffleHog against the saved Apktool output.
6. Generate reports and reconcile every artifact in the acquisition run.

A failed download, verification, or Apktool stage stops the pipeline before TruffleHog starts. The exact run ID is carried into each processing stage; unrelated workspace downloads are not swept into the run. Logs, decoded output, verification evidence, and reports remain in the configured workspace.

For a manual staged run, the equivalent commands are `apkworkbench discover`, `apkworkbench download`, `apkworkbench verify-downloads --run-id RUN_ID`, `apkworkbench decompile --run-id RUN_ID`, `apkworkbench analyze --run-id RUN_ID`, `apkworkbench report`, and finally `apkworkbench reconcile --run-id RUN_ID`.

The older 15,000-app acquisition helper remains separate and does not replace this end-to-end workflow.

## Exit statuses

| Code | Meaning |
|---:|---|
| 0 | Command completed without a reported error |
| 1 | Command failed or one or more items need attention |
| 2 | Fewer new applications were available than requested |

See [reliability and recovery](reliability-and-recovery.md) for failure handling and reconciliation.
