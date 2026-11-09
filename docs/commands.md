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
| `doctor` | Check Play client, Java, JADX, Apktool, and TruffleHog |
| `discover` | Collect package IDs from Google Play charts, categories, searches, or a package file |
| `download` | Freeze delivery hashes and download complete Play app bundles |
| `verify-downloads` | Independently re-hash and verify every file in a completed acquisition run |
| `decompile` | Run JADX and Apktool on acquired APK components |
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

## Phase One: enumeration and download only

Run the focused Phase One workflow from the repository root:

```bash
bash scripts/phase_one_google_play.sh
```

The runner performs only these stages, in order:

1. Discover package IDs from the Google Play Tools category and a file-manager search.
2. Download one new, available app bundle (including all APK splits and any OBB files).
3. Independently verify the on-disk files against the immutable run CSV and the bundle JSON.
4. Reconcile the acquisition attempts and download-history ledger.

It does **not** call `apkworkbench run`, JADX, Apktool, TruffleHog, or any other downstream analyzer. The default discovery cap is 30 and the default acquisition target is one app. Override the defaults with:

- `APKWORKBENCH_PHASE1_QUERY` (default: `file manager`)
- `APKWORKBENCH_PHASE1_CATEGORY` (default: `TOOLS`)
- `APKWORKBENCH_PHASE1_DISCOVERY_LIMIT` (default: `30`)
- `APKWORKBENCH_PHASE1_APK_COUNT` (default: `1`)

The script uses the configured APK Workbench workspace. Logs are written to its `logs/` directory; APK/OBB files remain under `downloads/`; and the independent verification report is written under `reports/`.

The current `main` Google Play adapter uses the saved `playstore-cli` local session described above. The anonymous Aurora/Goopdl experiment is kept on a separate branch and is not used by this Phase One runner.

For an existing completed run, verify it again without downloading:

```bash
apkworkbench verify-downloads --run-id RUN_ID
apkworkbench reconcile --run-id RUN_ID
```


## Processing

```bash
apkworkbench decompile --run-id RUN_ID
apkworkbench analyze --run-id RUN_ID
apkworkbench report
apkworkbench reconcile --run-id RUN_ID
```

Each APK component is independently re-hashed before JADX and Apktool. TruffleHog selects verified results with `--results=verified`; findings not explicitly marked verified are rejected.

## Full pipeline

```bash
apkworkbench run --apk-count 100

# Resumable 15,000-app target, in batches of 100.
scripts/acquire_15000_google_play.sh
```

The pipeline passes the exact run ID to decompilation and analysis; it does not sweep unrelated workspace downloads into the batch. The 15,000-app helper runs 150 batches of 100 sequentially, stops on the first incomplete batch, and can be rerun because already acquired Google Play package IDs are skipped.

## Exit statuses

| Code | Meaning |
|---:|---|
| 0 | Command completed without a reported error |
| 1 | Command failed or one or more items need attention |
| 2 | Fewer new applications were available than requested |

See [reliability and recovery](reliability-and-recovery.md) for failure handling and reconciliation.
