# APK WORKBENCH

**Google Play Store discovery · verified APK bundle acquisition · decompilation · static analysis · reporting**

APK Workbench is a Linux-native Python CLI for discovering Android apps on Google Play, acquiring their complete Play-delivered APK bundles, verifying each component against hashes supplied by Google Play, decoding APK components with Apktool, performing broad static surface inspection, scanning for verified secrets with TruffleHog, generating a consolidated evidence report, and reconciling every item in the run manifest.

**Acquisition source policy: Google Play Store only.** There is no alternate repository, mirror, or source fallback.

## Important Google Play limitations

The acquisition adapter keeps [playstore-cli](https://pypi.org/project/playstore-cli/) 0.1.1 for Google's **unofficial internal Play API** protocol and Play delivery operations. [goopdl](https://pypi.org/project/goopdl/2.0.0/) 2.0.0 supplies Play device-session credentials in one of three operator-configured modes (`sources.google_play.auth_mode`,`docs/configuration.md`):

- **`account`** (recommended): your own Google account, registered via `goopdl auth login` or `GOOPDL_ACCOUNT_EMAIL`/`GOOPDL_AAS_TOKEN`. The Aurora dispenser is never contacted; acquisition stays working when the third-party dispenser is down.
- **`anonymous`**: Aurora Store's public token dispenser. No Google account is read; the adapter fails closed when account credentials are present. The dispenser is third-party and frequently unavailable or rate-limited.
- **`auto`** (default): account mode when configured, anonymous otherwise.

The Play API still receives a short-lived bearer token internally; goopdl caches and rotates it (by default under `~/.config/goopdl`, relocatable with `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME`) and honors `retry_after` windows before re-minting. The Play API remains unofficial.

The adapter currently targets free apps. Paid apps, unavailable versions, and apps incompatible with the selected device profile may not be downloadable through this path. Play may add a free app to the selected device profile's library as part of delivery acquisition. Play may also serve different APK variants depending on the selected device profile.

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

## Configure Google Play access

**Account mode (recommended).** Sign in once with a dedicated Google account:

```bash
source .venv/bin/activate
goopdl auth login        # browser sign-in; --manual works on headless machines
goopdl auth status
apkworkbench doctor      # should print: Play session source: ACCOUNT (...)
```

Prefer the environment over the saved account? Use `goopdl auth login --print` and export `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` instead.

**Anonymous dispenser mode.** No Google login, AAS token, API key, browser sign-in, or manually supplied bearer token is required: on the first Play request, APK Workbench obtains a short-lived anonymous device session from Aurora Store's public token dispenser, whose tokens goopdl maintains and refreshes automatically. Aurora's dispenser is third-party and often unavailable; prefer account mode for reliable overnight acquisition.

```yaml
# ~/.config/apkworkbench/config.yaml
sources:
  google_play:
    auth_mode: auto    # auto (default) | account | anonymous
```

The goopdl token cache defaults to `~/.config/goopdl`; set `GOOPDL_CONFIG_DIR` to relocate it. In `anonymous` mode the adapter deliberately refuses to read Google-account credentials; set `auth_mode=account` or `auto` for that.

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

# One-command full workflow: discover, acquire, verify, decode, inspect,
# scan verified secrets, report, and reconcile.
bash scripts/full_google_play_pipeline.sh

# Or process a catalogue that has already been discovered.
apkworkbench run --apk-count 100

# Resumable 15,000-app target: 150 sequential batches of 100.
scripts/acquire_15000_google_play.sh

apkworkbench status
apkworkbench reconcile --run-id YOUR-RUN-ID
```

The run manifest is frozen after Play delivery metadata and expected hashes have been retrieved, but before the first APK download. Each Google Play app may contain `base.apk`, multiple `split_*.apk` files, and OBB expansion files. All are retained in the app's bundle directory. APK components are recorded separately and independently processed; OBB files are preserved and integrity-checked but are not passed to APK decompilers.

## One-command output

The full pipeline prints live stage feedback and finishes with a single consolidated report pair:

```text
reports/runs/<RUN_ID>/final-report.json
reports/runs/<RUN_ID>/final-report.html
```

The final report contains the frozen manifest and download attempts, Play bundle metadata and independent verification, Apktool status/log references, the broad static surface inventory and findings, Androguard DEX method/call-site cross-references and permission API usage, the complete original `Verified=true` TruffleHog objects, the API/route catalog, client-library and header evidence, rate-limit/retry indicators, and run reconciliation. Per-APK reports and raw scanner evidence remain alongside it under `results/` and `reports/`.

The static surface pass inventories manifest/components/permissions, network-security configuration, API endpoints/domains/routes and HTTP client call sites, common headers, retry/backoff/rate-limit hints, WebView, dynamic loading, process execution, TLS/cryptography indicators, storage/query APIs, dependency fingerprints, resources and native libraries. It does not duplicate TruffleHog's generic secret scanning. Server-side API rate limits cannot be determined from static APK strings; the report says so explicitly. Static findings remain leads until independently confirmed.

## Commands

- `apkworkbench discover --help`
- `apkworkbench download --help`
- `apkworkbench decompile --help`
- `apkworkbench analyze --help`
- `apkworkbench report --run-id RUN_ID`
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

The upstream downloader validates every Play delivery component against the size and digest returned by Play (SHA-256 for APK files and SHA-1 for OBB files). APK Workbench independently re-hashes the acquired files and verifies APK SHA-256 values again before decompilation. A successful automated test run verifies mocked adapter, anonymous-session, and subprocess behavior; it does not prove that Aurora's public dispenser is reachable, that a specific app is downloadable for a device profile, or that an overnight 15,000-app acquisition will complete. Those require live validation on the operator's machine.

APK Workbench does not install or execute acquired apps. Treat APKs and all generated output as untrusted input.
