# APK WORKBENCH

**DISCOVER · DOWNLOAD · DECOMPILE · ANALYZE · CATALOGUE**

A Linux-native Python command-line workbench for acquiring Android APKs from F-Droid, verifying artifact integrity, decompiling with JADX and Apktool, scanning local decompilation output with TruffleHog, and producing sanitized reports.

**Design principle:** one artifact at a time, one subprocess at a time, explicit verification, persistent records.

## Start here

**New installation? Follow the complete [Installation and First Run Guide](docs/installation.md).** It contains the exact Debian/Ubuntu commands to install the system dependencies, clone the repository, create the Python environment, verify the tools, perform a first authenticated discovery, and process a small test batch.

For an experienced user, the short path is:

```bash
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench

sudo apt update
sudo apt install -y git python3 python3-venv python3-pip gnupg default-jre-headless curl unzip

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

apkworkbench doctor
apkworkbench discover --limit 20
```

The short path assumes JADX, Apktool, and TruffleHog have already been installed. Their exact installation steps are in the guide.

## What it does

| Command | Purpose |
|---|---|
| `apkworkbench doctor` | Check all required external executables |
| `apkworkbench discover` | Authenticate and parse the F-Droid repository index |
| `apkworkbench download` | Freeze a run manifest, acquire new unique APKs, and verify SHA-256 |
| `apkworkbench decompile` | Re-verify APKs, then run JADX and Apktool sequentially |
| `apkworkbench analyze` | Scan completed decompilations locally with TruffleHog |
| `apkworkbench report` | Generate per-APK JSON/HTML reports and aggregate sanitized findings |
| `apkworkbench status` | Summarize acquisition and processing state |
| `apkworkbench run` | Execute the pipeline in order |
| `apkworkbench version` | Print the installed version |

## Requirements

- Debian 13 or Ubuntu 22.04/24.04 (primary documented targets)
- Python 3.10+
- GnuPG
- Java 21 runtime (JADX requires 64-bit Java 11 or newer)
- JADX
- Apktool
- TruffleHog

The external tools are separate system dependencies and are not installed by `pip`. See [Installation and First Run](docs/installation.md).

TruffleHog must support the filesystem scanner and `--no-verification`, `--no-update`, `--json`, `--concurrency`, and `--fail-on-scan-errors`. The application checks the installed CLI before scanning and fails closed if the required behavior cannot be confirmed.

## First-run workflow

After completing the installation guide:

```bash
# Confirm all five external tools are installed and healthy.
apkworkbench doctor

# Authenticate the F-Droid index and inspect the latest package records.
apkworkbench discover --limit 20

# Start small: acquire three new unique APK binaries.
apkworkbench download --apk-count 3

# Process the acquired artifacts.
apkworkbench decompile --limit 3
apkworkbench analyze --limit 3
apkworkbench report
apkworkbench status
```

Once the first batch has been inspected, the full pipeline can be run with:

```bash
apkworkbench run --apk-count 10
```

See [Command Reference](docs/commands.md) for options and [Configuration](docs/configuration.md) for workspace, timeouts, and tool overrides.

## F-Droid trust and integrity model

The application retrieves `index-v2.json` and its detached `.asc` signature over HTTPS. It imports the OpenPGP public key into an application-specific GnuPG home, checks its full primary fingerprint against the configured pin, and verifies the detached signature before parsing index bytes.

Default repository-index signer primary fingerprint:

```text
37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89
```

This OpenPGP identity is distinct from Android APK signing-certificate fingerprints carried in the repository index. APK certificate fingerprints are metadata; they are not substituted for the repository-index signing key.

The client rejects HTTP redirects, bounds response sizes and request times, and fails closed on a bad signature or unexpected signer. The index-v2 `packages` object maps package IDs to version records. Each `versions` map is keyed by APK SHA-256 (which must equal `file.sha256`); numeric `manifest.versionCode` is a separate value.

## Acquisition and processing guarantees

- SHA-256 is the unique binary identity.
- Previously acquired hashes and duplicates in the current index selection are excluded.
- A UUID run manifest is atomically published before the first download.
- Downloads are sequential and streamed into temporary `.part` files.
- Both expected byte count and SHA-256 must match before atomic publication.
- Download history is append-only; attempts are recorded separately.
- Every APK is re-hashed before decompilation.
- JADX runs with one worker; Apktool runs afterward with one job.
- TruffleHog scans completed JADX and Apktool outputs sequentially.
- Credential verification is disabled. Findings are unverified indicators for manual review, not proof that a credential is valid or exploitable.
- Reports persist allowlisted metadata and one-way finding fingerprints, not raw or decoded secret values.

## Workspace

Runtime data is separate from the source checkout. Default location: `~/APK-Workbench/`.

```text
APK-Workbench/
├── database/
│   ├── download_history.csv
│   ├── download_attempts.csv
│   ├── processing_status.csv
│   └── run_manifests/
├── downloads/<package>/<versionCode>/<sha256>/app.apk
├── results/<package>/<versionCode>/<sha256>/
│   ├── jadx/
│   ├── apktool/
│   └── trufflehog/
├── reports/
│   ├── <package>/<versionCode>/<sha256>/
│   │   ├── report.json
│   │   └── report.html
│   └── findings.csv
└── logs/apkworkbench.log
```

Configuration, isolated GPG state, and workspace overrides are documented in [Configuration](docs/configuration.md). Keep the runtime workspace out of Git; generated APKs and scan results are not source files.

## Tests and quality checks

```bash
python -m pytest
ruff check .
```

GitHub Actions runs the test suite on Python 3.10, 3.11, and 3.12. Tests use generated local GPG keys and mocked network/subprocess behavior. Passing CI does **not** mean a live F-Droid download or real local decompilation/scan has been performed; the installation guide includes the first live smoke-test sequence.

## Project documentation

- [Installation and First Run](docs/installation.md)
- [CLI Command Reference](docs/commands.md)
- [Configuration Reference](docs/configuration.md)
- [F-Droid Source Verification Notes](docs/F-DROID-SOURCE-VERIFICATION.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [MIT License](LICENSE)

## Intended use

For authorized research, defensive security review, software inventory, and interoperability analysis. Only acquire or analyze applications you are legally entitled to review. Static scanner output must be manually validated and must not be represented as proof of exploitability.

## Project identity

**CO-DEVELOPED BY dial9 + ChatGPT**

**SLOW. SIMPLE. SEQUENTIAL. VERIFIED.**
