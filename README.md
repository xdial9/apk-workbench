# APK WORKBENCH

**Google Play Store discovery · verified APK bundle acquisition · decompilation · static analysis · reporting**

APK Workbench is a Linux-native Python CLI for discovering Android apps on Google Play, acquiring their complete Play-delivered APK bundles, verifying each component against hashes supplied by Google Play, and processing APK components with JADX, Apktool, and TruffleHog.

**Acquisition source policy: Google Play Store only.** There is no alternate repository, mirror, or source fallback.

## Important Google Play limitations

The acquisition adapter uses [playstore-cli](https://pypi.org/project/playstore-cli/) 0.1.1 for Google's unofficial internal Play API protocol and verified file delivery. It no longer reads a saved Google account or requires `playstore-cli login`.

By default, APK Workbench obtains short-lived **anonymous device-session credentials** from [Aurora Store's public token dispenser](https://auroraoss.com/api/auth), through [goopdl](https://github.com/Villoh/goopdl) 2.0.0. No Google account, AAS token, API key, browser sign-in, or user-supplied bearer token is required. The Play FDFE API itself still expects a bearer token; the dispenser issues it anonymously, and goopdl caches/rotates the short-lived tokens locally (normally under `~/.config/goopdl`). A dispenser outage or rate limit can temporarily stop new sessions. The adapter refuses to silently switch to Google-account mode: unset `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` if either is present.

Google Play's internal API is unofficial and may be subject to Google's terms and service-side restrictions. Aurora's dispenser is a third-party service, not Google. This does not change the acquisition source: app metadata and APK bundles still come from Google Play. The upstream client currently downloads free apps. Play may add a free app to the anonymous device profile's library as part of delivery acquisition. Play may also serve different APK variants depending on the selected device profile.

## Install

Supported runtime: Linux, Python 3.10+, Java 11+, JADX, Apktool, and TruffleHog.

```bash
sudo apt update
sudo apt install -y ca-certificates git curl unzip python3 python3-venv python3-pip default-jre-headless

git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Install JADX, Apktool, and TruffleHog using their official installation instructions. APK Workbench checks for `playstore-cli`, Java, JADX, Apktool, and TruffleHog with `apkworkbench doctor`.

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
