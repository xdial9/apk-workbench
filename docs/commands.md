# CLI Command Reference

All discovery and acquisition commands use Google Play Store. No other source is configured or used.

## Authentication prerequisite

APK Workbench obtains Play bearer tokens through goopdl in one of three modes,
selected in `~/.config/apkworkbench/config.yaml`:

```yaml
sources:
  google_play:
    auth_mode: auto   # auto (default) | account | anonymous
```

### Google account mode (recommended; stable)

```bash
goopdl auth login         # browser sign-in; saves the account, or use --manual
goopdl auth status        # confirm the saved account
```

goopdl registers a device for your account and exchanges its AAS token for a
short-lived Play bearer token. The Aurora dispenser is never contacted in
account mode. Use a dedicated account — Play may add a free app to the
account's library during delivery acquisition, and the unofficial API may
result in account restrictions.

Alternatively export `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` instead of
`goopdl auth login`.

### Anonymous dispenser mode (fallback)

No account is used; goopdl fetches anonymous device sessions from Aurora
Store's public token dispenser (`auroraoss.com`). This is third-party and
often unavailable or rate-limited.

| `auth_mode` | Behavior |
|---|---|
| `auto` (default) | Uses the account when one is configured (`goopdl auth login` or the two env vars); falls back to the anonymous dispenser otherwise |
| `account` | Google account only; fails fast with instructions when nothing is configured |
| `anonymous` | Public dispenser only; fails closed if `GOOPDL_ACCOUNT_EMAIL`/`GOOPDL_AAS_TOKEN` is set, and the dispenser is never used otherwise |

`apkworkbench doctor` prints the resolved session source.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Check Play client, Java, Apktool, and TruffleHog; report the resolved Play session source |
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
5. Run the built-in APK surface analyzer over Apktool output: manifest, components, permissions, API endpoints/routes/client call sites, headers, retry/rate-limit indicators, WebView, TLS/crypto, storage, dependencies, resources, and native-library inventory.
6. Run TruffleHog separately with `--results=verified`; the surface analyzer does not repeat TruffleHog's secret-detection job.
7. Generate per-APK reports plus one consolidated JSON/HTML run report, then reconcile every manifest item.

A failed download or verification stops processing because the acquired inputs are not trusted. Apktool is evaluated per APK: successful outputs and non-zero/terminated runs that leave usable decoded files are saved transactionally; the latter are marked `partial`. The built-in static surface analyzer and TruffleHog operate as separate analysis passes over saved Apktool output. TruffleHog scans every saved `success` or `partial` Apktool output and skips APKs with no usable decoded files. If no usable output exists in the run, analysis is recorded as skipped. Per-APK failures remain visible in the final report and run reconciliation. The consolidated report is written to `reports/runs/RUN_ID/final-report.json` and `final-report.html`. The exact run ID is carried into each processing stage; unrelated workspace downloads are not swept into the run. Live terminal feedback includes measured transfer/hash byte progress, Apktool output and elapsed-time activity, TruffleHog scan activity/verified-finding counters, and stage summaries.

For a manual staged run, the individual commands remain available. The full wrapper is preferred for normal use because it performs discovery, verification, both analysis passes, report generation and reconciliation automatically.

The older 15,000-app acquisition helper remains separate and does not replace this end-to-end workflow.

## Exit statuses

| Code | Meaning |
|---:|---|
| 0 | Command completed without a reported error |
| 1 | Command failed or one or more items need attention |
| 2 | Fewer new applications were available than requested |

See [reliability and recovery](reliability-and-recovery.md) for failure handling and reconciliation.
