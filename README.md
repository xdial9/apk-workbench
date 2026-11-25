# APK WORKBENCH

**Google Play Store discovery · verified APK bundle acquisition · decompilation · static analysis · AI handoff reporting**

APK Workbench is a Linux-native Python CLI for acquiring Android APKs (from Google Play or local APK files), verifying component integrity, decoding APK components with Apktool, performing deterministic static surface and DEX/native analysis, scanning for secrets with TruffleHog, generating consolidated evidence reports, and packaging frozen, self-contained AI handoff bundles.

**Acquisition source policy: Google Play Store (or operator-supplied local APKs).** There is no alternate repository, mirror, or source fallback.

## Install

Supported runtime: **Linux**, **Python 3.10+**, **Java 11+**, **Apktool**, and **TruffleHog**.

### 1. Install `apkworkbench`

From PyPI:

```bash
pip install apkworkbench
```

From source (for development):

```bash
git clone --branch main https://github.com/xdial9/apk-workbench.git
cd apk-workbench

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### 2. Install system requirements

APK Workbench shells out to three external system tools:

- **Java 11+** (required by Apktool):
  ```bash
  sudo apt update && sudo apt install -y default-jre-headless
  ```
- **Apktool** (`apktool` on `PATH`): install via your distro package manager or the [official Apktool installation guide](https://apktool.org/docs/install).
- **TruffleHog** (`trufflehog` on `PATH`): install via the [official TruffleHog releases](https://github.com/trufflesecurity/trufflehog/releases) or install script.

### 3. Verify your environment

```bash
apkworkbench doctor
```

`apkworkbench doctor` verifies `java`, `apktool`, `trufflehog`, `playstore-cli`, and `androguard`, checks workspace home health and bundled AI prompts, reports the active Google Play auth mode, and prints actionable install hints if any system tool is missing.

## Quick Start

```bash
# 1. Verify system tools, workspace, and Play auth status
apkworkbench doctor

# 2. Run the full pipeline on a Google Play package
apkworkbench run --package com.example.app

#    Or run the full self-contained pipeline on a local APK
apkworkbench run --local-apk /path/to/base.apk

# 3. Override the default ~/APK-Workbench home directory if desired
apkworkbench --workspace /path/to/home run --local-apk /path/to/base.apk
#    Or set the environment variable:
export APKWORKBENCH_WORKSPACE=/path/to/home
```

## Single-Folder Layout

All configuration, run indexes, logs, and self-contained run bundles live under a single folder: **`~/APK-Workbench/`** (overridable via `--workspace` or `APKWORKBENCH_WORKSPACE`).

```text
~/APK-Workbench/
├── config.yaml                          # Workbench configuration
├── runs_index.json                      # Index of every completed and in-progress run
├── logs/                                # Global workbench logs
└── runs/
    └── <package>-v<version>-<short_id>/ # Self-contained per-run bundle
```

Every run creates one self-contained directory under `runs/` with all inputs, decoded evidence, reports, hashes, prompts, and AI analysis workspace together (with no second Apktool directory):

```text
~/APK-Workbench/runs/<package>-v<version>-<short_id>/
├── README.md          # Human-readable guide to this run
├── README.txt         # Short bootstrap pointer for AI consumers
├── handoff.json       # Schema/tool/prompt versions, bundle_id, and key file hashes
├── hashes.sha256      # SHA-256 manifest over all frozen evidence files
├── apk/               # Original APK(s) and split/OBB components for this run
├── apktool/           # Decoded APK components (apktool/<component>/)
├── surface/           # Static surface, DEX, native, facts.jsonl, location_map.json
├── trufflehog/        # Verified and unverified TruffleHog findings + status.json
├── manifest/          # Frozen run manifest and verification records
├── reports/           # final-report.json and final-report.html
├── stages/            # Per-stage status.json records
├── logs/              # Run-scoped stage logs
├── prompts/           # Bundled AI handoff prompts (0.txt–6.txt)
└── ai_analysis/       # Writable AI analysis output area (attempt-01/, etc.)
```

**Backward compatibility:** `APKWORKBENCH_WORKSPACE` overrides the default `~/APK-Workbench` home directory, and if `~/APK-Workbench/config.yaml` does not exist yet, APK Workbench falls back to reading a legacy `~/.config/apkworkbench/config.yaml` automatically.

## How to Find & Read a Run's Output

1. Locate the run folder under `~/APK-Workbench/runs/<package>-v<version>-<short_id>/` (or look up the path and metadata in `~/APK-Workbench/runs_index.json`).
2. Start with `README.md` at the top of the run folder for a quick map of the run's files and status.
3. Review the key outputs:
   - **AI Dossier:** `ai_analysis/attempt-01/dossier.md`
   - **Lead Ledger:** `ai_analysis/attempt-01/lead_ledger.json`
   - **Consolidated Reports:** `reports/final-report.html` (human view) and `reports/final-report.json` (structured data)
4. Verify evidence integrity at any time:
   ```bash
   apkworkbench verify-workspace ~/APK-Workbench/runs/<run-folder>
   ```

The consolidated report contains the frozen manifest and acquisition records, Play bundle metadata and independent verification, Apktool status/log references, the broad static surface inventory and findings, Androguard DEX method/call-site cross-references and permission API usage, TruffleHog findings, the API/route catalog, client-library and header evidence, rate-limit/retry indicators, and run reconciliation.

The static surface pass inventories manifest/components/permissions, network-security configuration, API endpoints/domains/routes and HTTP client call sites, common headers, retry/backoff/rate-limit hints, WebView, dynamic loading, process execution, TLS/cryptography indicators, storage/query APIs, dependency fingerprints, resources, and native libraries. Server-side API rate limits cannot be determined from static APK strings; the report states so explicitly. Static findings remain leads until independently confirmed.

## Migrating Existing 0.2.0 Workspaces

If you have an existing 0.2.0 workspace split across `~/.config/apkworkbench`, `~/.local/state/apkworkbench`, and a project directory, preview and migrate it into `~/APK-Workbench`:

```bash
# Preview what will be moved/indexed without modifying files
apkworkbench migrate --source /path/to/old/workspace --target ~/APK-Workbench --dry-run

# Apply the migration
apkworkbench migrate --source /path/to/old/workspace --target ~/APK-Workbench --apply
```

## Important Google Play limitations

The acquisition adapter uses [playstore-cli](https://pypi.org/project/playstore-cli/) 0.1.1 for Google's **unofficial internal Play API** protocol and Play delivery operations. [goopdl](https://pypi.org/project/goopdl/2.0.0/) 2.0.0 supplies Play device-session credentials in one of three operator-configured modes (`sources.google_play.auth_mode`, see [docs/configuration.md](docs/configuration.md)):

- **`account`** (recommended): your own Google account, registered via `goopdl auth login` or `GOOPDL_ACCOUNT_EMAIL`/`GOOPDL_AAS_TOKEN`. The Aurora dispenser is never contacted; acquisition stays working when the third-party dispenser is down.
- **`anonymous`**: Aurora Store's public token dispenser. No Google account is read; the adapter fails closed when account credentials are present. The dispenser is third-party and frequently unavailable or rate-limited.
- **`auto`** (default): account mode when configured, anonymous otherwise.

The Play API still receives a short-lived bearer token internally; `goopdl` caches and rotates it (by default under `~/.config/goopdl`, relocatable with `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME`) and honors `retry_after` windows before re-minting. The Play API remains unofficial.

The adapter currently targets free apps. Paid apps, unavailable versions, and apps incompatible with the selected device profile may not be downloadable through this path. Play may add a free app to the selected device profile's library as part of delivery acquisition. Play may also serve different APK variants depending on the selected device profile.

## Configure Google Play access

**Account mode (recommended).** Sign in once with a dedicated Google account:

```bash
goopdl auth login        # browser sign-in; --manual works on headless machines
goopdl auth status
apkworkbench doctor      # should print: Play session source: ACCOUNT (...)
```

Prefer the environment over the saved account? Use `goopdl auth login --print` and export `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` instead.

**Anonymous dispenser mode.** No Google login, AAS token, API key, browser sign-in, or manually supplied bearer token is required: on the first Play request, APK Workbench obtains a short-lived anonymous device session from Aurora Store's public token dispenser, whose tokens `goopdl` maintains and refreshes automatically. Aurora's dispenser is third-party and often unavailable; prefer account mode for reliable overnight acquisition.

```yaml
# ~/APK-Workbench/config.yaml
sources:
  google_play:
    auth_mode: auto    # auto (default) | account | anonymous
```

The `goopdl` token cache defaults to `~/.config/goopdl`; set `GOOPDL_CONFIG_DIR` to relocate it. In `anonymous` mode the adapter deliberately refuses to read Google-account credentials; set `auth_mode: account` or `auto` for that.

## Discover a corpus & batch processing

```bash
# Discover up to 15,000 unique package IDs across Play top-free charts
apkworkbench discover --limit 15000

# Add targeted Play searches to expand the candidate set
apkworkbench discover --limit 15000 \
  --query banking --query finance --query fintech \
  --query wallet --query payments --query neobank

# Restrict discovery to selected Play categories
apkworkbench discover --category FINANCE --category APPLICATION --limit 1000

# Import only the listed IDs (one per line), without crawling Play charts
apkworkbench discover --packages-file packages.txt --limit 15000

# Download or process batches from the discovered catalog
apkworkbench download --apk-count 100
apkworkbench run --apk-count 100
apkworkbench status
apkworkbench reconcile --run-id YOUR-RUN-ID
```

Discovery results are de-duplicated by Android package ID. A requested limit is a ceiling, not a guarantee: Play search and chart endpoints return bounded result sets, and discovery can produce fewer than 15,000 unique apps. To combine a package-ID list with broad discovery, also provide a query or category explicitly.

The run manifest is frozen after Play delivery metadata and expected hashes have been retrieved, before the first APK download. Each Google Play app may contain `base.apk`, multiple `split_*.apk` files, and OBB expansion files; all are retained in the run's `apk/` directory. APK components are recorded separately and independently processed; OBB files are preserved and integrity-checked without being passed to APK decompilers.

## Commands

- `apkworkbench doctor`
- `apkworkbench run --help`
- `apkworkbench discover --help`
- `apkworkbench download --help`
- `apkworkbench decompile --help`
- `apkworkbench analyze --help`
- `apkworkbench report --run-id RUN_ID`
- `apkworkbench status`
- `apkworkbench reconcile --run-id RUN_ID`
- `apkworkbench verify-workspace RUN_DIR`
- `apkworkbench migrate --help`

See [CLI reference](docs/commands.md), [configuration](docs/configuration.md), [installation](docs/installation.md), and [reliability and recovery](docs/reliability-and-recovery.md).

The active, evidence-gated plan for the first fresh one-app pipeline run is the [First Fresh Full-Pipeline Run guide](docs/engineering/FIRST-FULL-PIPELINE-PLAN.md).

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

## License

MIT License — see [LICENSE](LICENSE).
