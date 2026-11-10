# APK WORKBENCH

**Google Play Store discovery · verified APK bundle acquisition · decompilation · static analysis · reporting**

APK Workbench is a Linux-native Python CLI for discovering Android apps on Google Play, acquiring their complete Play-delivered APK bundles, verifying each component against hashes supplied by Google Play, and decoding APK components with Apktool and scanning the decoded output with TruffleHog.

**Acquisition source policy: Google Play Store only.** There is no alternate repository, mirror, or source fallback.

## Important Google Play limitations

The acquisition adapter uses [playstore-cli](https://pypi.org/project/playstore-cli/) 0.1.1, an alpha research client for Google's **unofficial internal Play API**. It is not an official Google API and may violate Google's terms or cause the research account to be restricted. Use a dedicated Google account, not your primary account. The upstream client stores a long-lived AAS token locally; protect its configuration directory and never share or commit it.

The upstream client currently downloads free apps. Paid apps, unavailable versions, and apps incompatible with the selected device profile cannot be acquired through this path. A free app that is not already in the research account's Play library may be added to that account as part of delivery acquisition. Review this account-side effect before using the research account. Play may serve different APK variants depending on the device profile.

## Install

Supported runtime: Linux, Python 3.10+, Java 11+, Apktool, and TruffleHog.

```bash
sudo apt update
sudo apt install -y ca-certificates git curl unzip python3 python3-venv python3-pip default-jre-headless

git clone --branch fix/apktool-only-trufflehog-pipeline https://github.com/xdial9/apk-workbench.git
cd apk-workbench

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Install Apktool and TruffleHog using their official installation instructions. APK Workbench checks for `playstore-cli`, Java, Apktool, and TruffleHog with `apkworkbench doctor`.

## Authenticate Google Play locally

The Play client is installed in the same Python environment as APK Workbench.

```bash
source .venv/bin/activate
playstore-cli login
playstore-cli checkin
apkworkbench doctor
```

Complete browser sign-in and any two-step verification locally. Do not paste Google credentials, cookies, AAS tokens, or session files into ChatGPT or GitHub. The first check-in registers a virtual device; choose a device profile compatible with the apps you intend to acquire.

## Discover a corpus

```bash
# Discover up to 15,000 unique package IDs across Play top-free charts.
apkworkbench discover --limit 15000

# Add targeted Play searches to expand the candidate set.
apkworkbench discover --limit 15000 \
  --query banking --query finance --query fintech \
  --query wallet --query payments --query neobank

# Restrict discovery to selected Play categories.
apkworkbench discover --category FINANCE --category APPLICATION --limit 1000

# Import known package IDs (one per line), while retaining Play as the only source.
apkworkbench discover --packages-file packages.txt --limit 15000
```

Discovery results are de-duplicated by Android package ID and stored in `database/google_play_discovery.csv`. A requested limit is a ceiling, not a guarantee: Play search and chart endpoints return bounded result sets, and discovery can produce fewer than 15,000 unique apps. Supply additional search queries or a package-ID list to expand coverage.

## Acquire and process

```bash
# First 100 newly catalogued Google Play apps.
apkworkbench download --apk-count 100

# Or run acquisition, decompilation, analysis, reporting, and reconciliation.
apkworkbench run --apk-count 100

# Resumable 15,000-app target: 150 sequential batches of 100.
scripts/acquire_15000_google_play.sh

apkworkbench status
apkworkbench reconcile --run-id YOUR-RUN-ID
```

The run manifest is frozen after Play delivery metadata and expected hashes have been retrieved, but before the first APK download. Each Google Play app may contain `base.apk`, multiple `split_*.apk` files, and OBB expansion files. All are retained in the app's bundle directory. APK components are recorded separately and independently processed; OBB files are preserved and integrity-checked but are not passed to APK decompilers.

## Commands

- `apkworkbench discover --help`
- `apkworkbench download --help`
- `apkworkbench decompile --help`
- `apkworkbench analyze --help`
- `apkworkbench report`
- `apkworkbench status`
- `apkworkbench reconcile --run-id RUN_ID`
- `apkworkbench doctor`

See [CLI reference](docs/commands.md), [configuration](docs/configuration.md), [installation](docs/installation.md), and [reliability and recovery](docs/reliability-and-recovery.md).

## Project history and engineering references

This repository preserves the actual development history, including earlier F-Droid work, the Google Play pivot, reliability corrections, and the evolution of the analysis architecture. Earlier approaches and mistakes remain part of the record.

- [Project history](docs/PROJECT_HISTORY.md)
- [Target architecture](docs/architecture/TARGET_ARCHITECTURE.md)
- [Evidence schema](docs/architecture/EVIDENCE_SCHEMA.md)
- [Airtable engineering map](docs/engineering/AIRTABLE_ENGINEERING_MAP.md)
- [Complete Airtable snapshot](docs/engineering/airtable-snapshot.json)

Airtable is the engineering coordination mirror. Runtime APK data remains local to the workbench.

## Verification boundary

The upstream downloader validates every Play delivery component against the size and digest returned by Play (SHA-256 for APK files and SHA-1 for OBB files). APK Workbench independently re-hashes the acquired files and verifies APK SHA-256 values again before decompilation. A successful automated test run verifies mocked adapter and subprocess behavior; it does not prove that a live Google account can authenticate, that a specific app is downloadable for a device profile, or that an overnight 15,000-app acquisition will complete. Those require live validation on the operator's machine.

APK Workbench does not install or execute acquired apps. Treat APKs and all generated output as untrusted input.
