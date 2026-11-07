# APK WORKBENCH

**DISCOVER | DOWNLOAD | DECOMPILE | ANALYZE | CATALOGUE**

A Linux-native Python CLI for acquiring Android APKs from F-Droid, verifying artifact integrity, decompiling with JADX and Apktool, scanning local decompilation output with TruffleHog, and producing sanitized reports.

The execution model is deliberately simple: **one artifact at a time, one subprocess at a time, with persistent records and explicit verification**.

## Current capabilities

| Command | Function |
|---|---|
| `apkworkbench doctor` | Check required external tools and executable health |
| `apkworkbench discover` | Authenticate and parse the F-Droid repository index |
| `apkworkbench download` | Select new unique APK binaries, freeze a run manifest, download sequentially, and verify SHA-256 |
| `apkworkbench decompile` | Re-check APK integrity, then run JADX and Apktool sequentially |
| `apkworkbench analyze` | Scan completed decompilations locally with TruffleHog |
| `apkworkbench report` | Generate per-APK JSON and HTML reports |
| `apkworkbench status` | Summarize acquisition and processing state |
| `apkworkbench run` | Run acquisition, decompilation, analysis, and reporting in order |
| `apkworkbench version` | Print the package version |

## Requirements

- Linux (Debian 13 and Ubuntu 22.04/24.04 are primary targets)
- Python 3.10+
- GnuPG
- Java runtime supported by the installed JADX build
- JADX
- Apktool
- TruffleHog for the analysis stage

TruffleHog must expose the `filesystem` command and the `--no-verification`, `--no-update`, `--json`, `--concurrency`, and `--fail-on-scan-errors` options. The wrapper checks the installed command's help before starting a scan. If the no-verification control cannot be confirmed, scanning fails closed.

## Install

Create and activate a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Install the external tools using their official installation instructions. Then check the environment:

```bash
apkworkbench doctor
```

## Quick start

First inspect the authenticated index without downloading anything:

```bash
apkworkbench discover --limit 20
```

Select and acquire ten new APK binaries:

```bash
apkworkbench download --apk-count 10
```

Run the remaining stages:

```bash
apkworkbench decompile
apkworkbench analyze
apkworkbench report
apkworkbench status
```

Or run all stages in sequence:

```bash
apkworkbench run --apk-count 10
```

Restrict discovery/acquisition to one exact Android package ID:

```bash
apkworkbench discover --package org.example.app
apkworkbench download --apk-count 3 --package org.example.app
```

Use `--force` with `decompile` or `analyze` only when intentionally repeating completed work. Use `--limit N` to cap a decompilation or scan pass.

## F-Droid trust and integrity model

The application retrieves the F-Droid `index-v2.json` file and its detached `.asc` signature over HTTPS. It imports the OpenPGP public key into an application-specific GnuPG home, checks its full primary fingerprint against the configured pin, and verifies the detached signature before parsing index bytes.

Default repository-index signer primary fingerprint:

```text
37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89
```

This OpenPGP identity is distinct from the Android APK signing-certificate fingerprints carried in the repository index. APK certificate fingerprints are retained as metadata; they are not substituted for the repository-index signing key.

The application rejects HTTP redirects, bounds index/key/signature response sizes, and applies request timeouts. A failed signature or unexpected signer is a hard failure.

The index-v2 `packages` object maps package IDs to version records. Each `versions` map is keyed by the APK SHA-256 digest (which must equal `file.sha256`); the APK's numeric `manifest.versionCode` is a separate field. Repository `file.name` paths may begin with one slash and are normalized as paths relative to the repository root.

## Acquisition model

- Binary identity is SHA-256, not package name or version label.
- Existing history hashes are excluded from selection.
- Duplicate hashes within the same index selection are selected once.
- Newer versions are considered across packages before older versions.
- The requested count refers to unique binary hashes.
- If fewer new unique binaries exist than requested, the exact shortfall is printed.
- A UUID run manifest is atomically published before the first APK download.
- APKs download sequentially into temporary `.part` files.
- The expected byte count and SHA-256 must both match before the APK is renamed into its permanent location and added to download history.
- Download history is append-only. Failed and successful attempts are recorded separately.

## Decompilation and analysis

Every APK is SHA-256 checked again before it is passed to a decompiler.

JADX runs with a single worker. Apktool runs afterward with one job. Their stdout/stderr and return codes are written to separate logs. Processing state is updated atomically.

Only artifacts for which both decompilers succeeded are eligible for TruffleHog scanning. TruffleHog scans the JADX and Apktool output directories sequentially. Active credential verification is explicitly disabled. Findings are treated as unverified indicators for manual review, not proof that a credential is valid or exploitable.

## Reports and redaction

Per-artifact reports are written to:

```text
reports/<package>/<versionCode>/<sha256>/report.json
reports/<package>/<versionCode>/<sha256>/report.html
```

The aggregate sanitized findings CSV is:

```text
reports/findings.csv
```

Reports include detector identifiers, file paths, line numbers, and one-way fingerprints. Raw secret values, decoded secret values, and arbitrary TruffleHog metadata are not copied into the report dataset.

## Workspace layout

The runtime workspace is separate from the source checkout. By default it is `~/APK-Workbench`.

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
│   ├── trufflehog/
│   ├── jadx.log
│   └── apktool.log
├── reports/
│   ├── <package>/<versionCode>/<sha256>/
│   │   ├── report.json
│   │   └── report.html
│   └── findings.csv
└── logs/apkworkbench.log
```

Configuration and application state are stored separately:

- Config: `~/.config/apkworkbench/config.yaml`
- Isolated GPG home: `~/.local/state/apkworkbench/gpg`
- Workspace override: `APKWORKBENCH_WORKSPACE`
- Config directory override: `APKWORKBENCH_CONFIG_DIR`
- State directory override: `APKWORKBENCH_STATE_DIR`

A YAML configuration file can override defaults. See [docs/configuration.md](docs/configuration.md).

## Tests

```bash
python -m pytest
ruff check .
```

Unit tests use generated local GPG keys and mocked HTTP/subprocess responses. CI does not need a live F-Droid download or live TruffleHog scan.

## Intended use

APK WORKBENCH is for authorized research, defensive security review, software inventory, and interoperability analysis. Do not acquire or analyze applications without the legal right or authorization to do so. Do not treat static scanner results as proof of exploitability.

## Project identity

**CO-DEVELOPED BY dial9 + ChatGPT**

**SLOW. SIMPLE. SEQUENTIAL. VERIFIED.**
