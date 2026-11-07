![APK WORKBENCH](docs/assets/apk-workbench-banner.svg)

[![Tests](https://github.com/xdial9/apk-workbench/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/xdial9/apk-workbench/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-333333?logo=linux&logoColor=white)](https://www.debian.org/)
[![License](https://img.shields.io/badge/License-MIT-2E8B57.svg)](LICENSE)

# APK WORKBENCH

**DISCOVER · DOWNLOAD · DECOMPILE · ANALYZE · CATALOGUE**

A Python-only, Linux-native command-line workbench for authenticated F-Droid discovery, verified APK acquisition, sequential decompilation, local static analysis, and sanitized reporting.

> **Operating model:** one artifact at a time · one external process at a time · verified inputs · persistent records.

**CO-DEVELOPED BY dial9 + ChatGPT**  
*SLOW. SIMPLE. SEQUENTIAL. VERIFIED.*

---

## 01 · Install the complete toolchain

Supported installation path: 64-bit Debian 13 and Ubuntu 22.04/24.04. APK WORKBENCH itself is Python; Java, GnuPG, JADX, Apktool, and TruffleHog are separate system dependencies.

### A. System packages

~~~bash
sudo apt update
sudo apt install -y \
  ca-certificates git curl unzip gnupg \
  python3 python3-venv python3-pip default-jre-headless

python3 --version
java -version
gpg --version
~~~

Python 3.10 or newer is required. JADX 1.5.6 requires a 64-bit Java 11-or-newer runtime.

### B. JADX 1.5.6

~~~bash
mkdir -p "$HOME/.local/opt" "$HOME/.local/bin"
cd /tmp

curl -fL --retry 3 \
  -o jadx-1.5.6.zip \
  https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip

unzip -q -o jadx-1.5.6.zip -d "$HOME/.local/opt/jadx-1.5.6"

cat > "$HOME/.local/bin/jadx" <<'EOF'
#!/bin/sh
exec "$HOME/.local/opt/jadx-1.5.6/bin/jadx" "$@"
EOF
chmod 0755 "$HOME/.local/bin/jadx"
~~~

### C. Apktool 3.0.3

~~~bash
mkdir -p "$HOME/.local/opt/apktool-3.0.3" "$HOME/.local/bin"

curl -fL --retry 3 \
  -o "$HOME/.local/opt/apktool-3.0.3/apktool.jar" \
  https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar

printf '%s  %s\n' \
  'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423' \
  "$HOME/.local/opt/apktool-3.0.3/apktool.jar" | sha256sum -c -

cat > "$HOME/.local/bin/apktool" <<'EOF'
#!/bin/sh
exec java -jar "$HOME/.local/opt/apktool-3.0.3/apktool.jar" "$@"
EOF
chmod 0755 "$HOME/.local/bin/apktool"
~~~

The checksum must report **OK**. Stop if it does not.

### D. User-local PATH and TruffleHog

~~~bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.profile" || \
  printf '\n# APK WORKBENCH user-local tools\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.profile"
export PATH="$HOME/.local/bin:$PATH"

curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | \
  sudo sh -s -- -b /usr/local/bin

jadx --version
apktool --version
trufflehog --version
~~~

TruffleHog must advertise the filesystem scanner and the safe-operation flags checked by the application: **--no-verification**, **--no-update**, **--json**, **--concurrency**, and **--fail-on-scan-errors**.

### E. Clone and install APK WORKBENCH

~~~bash
cd "$HOME"
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

apkworkbench version
apkworkbench doctor
~~~

All five required executables—GnuPG, Java, JADX, Apktool, and TruffleHog—must show **[OK]** in the environment check.

---

## 02 · Authenticate F-Droid discovery

~~~bash
apkworkbench discover --limit 20
apkworkbench discover --refresh-index
~~~

The client retrieves the F-Droid signing key, signed index, and detached signature over HTTPS. It checks the imported OpenPGP primary fingerprint and verifies the detached signature **before parsing any index metadata**.

The signed index and detached signature are cached under **~/.local/state/apkworkbench/fdroid-cache/** for six hours by default. Cached data is cryptographically re-verified on every use. Use **--refresh-index** with **discover**, **download**, or **run** to bypass the cache and retrieve a fresh signed copy.

A successful discovery reports **Index signature: VERIFIED**. Progress messages show the active retrieval phase and index byte counts. Discovery does not download APKs.

---

## 03 · Run the first complete batch

Start with three new APK binaries:

~~~bash
apkworkbench run --apk-count 3
apkworkbench status
~~~

The full pipeline performs authenticated discovery, selection, immutable manifest publication, sequential downloads, SHA-256/size validation, JADX, Apktool, TruffleHog, and report generation.

**Batch boundary:** the run passes its exact frozen manifest into decompilation and analysis. It does not silently sweep older downloads into the new batch. Failed downloads are skipped, not substituted with unrelated workspace artifacts.

---

## 04 · Command reference

### Environment and help

~~~bash
apkworkbench --help
apkworkbench doctor
apkworkbench version
~~~

### Discover packages

~~~bash
apkworkbench discover
apkworkbench discover --limit 50
apkworkbench discover --package org.example.app
apkworkbench discover --refresh-index
~~~

The limit controls display count only. Package filtering is an exact Android application ID match.

### Download unique APKs

~~~bash
apkworkbench download
apkworkbench download --apk-count 3
apkworkbench download --apk-count 10 --package org.example.app
~~~

The command prints a UUID **Run ID** and the frozen manifest path. Save the ID when processing stages separately.

### Decompile

~~~bash
apkworkbench decompile
apkworkbench decompile --limit 5
apkworkbench decompile --run-id YOUR-RUN-ID
apkworkbench decompile --run-id YOUR-RUN-ID --force
~~~

Without a run ID, standalone decompilation considers all eligible workspace downloads. With a run ID, it processes only successfully acquired artifacts in that manifest.

### Analyze

~~~bash
apkworkbench analyze
apkworkbench analyze --limit 5
apkworkbench analyze --run-id YOUR-RUN-ID
apkworkbench analyze --run-id YOUR-RUN-ID --force
~~~

Without a run ID, standalone analysis considers all eligible completed workspace decompilations. With a run ID, it scans only the matching acquisition batch.

Credential verification is disabled. Findings are unverified indicators for manual review—not proof of valid credentials or exploitability.

### Reports and status

~~~bash
apkworkbench report
apkworkbench status
~~~

Reports are refreshed for the workspace catalogue, not just the most recent run.

### Full pipeline

~~~bash
apkworkbench run
apkworkbench run --apk-count 3
apkworkbench run --apk-count 25
apkworkbench run --apk-count 10 --package org.example.app
apkworkbench run --apk-count 10 --force-decompile --force-analyze
apkworkbench run --apk-count 10 --refresh-index
~~~

| Option | Purpose |
|---|---|
| **--apk-count INTEGER** | New unique APKs to select; default 10 |
| **--package TEXT** | Exact package ID filter |
| **--force-decompile** | Repeat successful decompilation for this batch |
| **--force-analyze** | Repeat successful scans for this batch |

See the [CLI Command Reference](docs/commands.md) for every option and exit status.

See [Retry-safe decompilation](docs/retry-safe-decompilation.md) for independent per-tool resume and non-destructive output replacement.

---

## 05 · Runtime workspace

The source checkout and runtime data are separate. Default workspace:

~~~text
~/APK-Workbench/
~~~

~~~text
APK-Workbench/
├── database/
│   ├── download_history.csv
│   ├── download_attempts.csv
│   ├── processing_status.csv
│   └── run_manifests/
├── downloads/<package>/<versionCode>/<sha256>/app.apk
├── results/<package>/<versionCode>/<sha256>/
│   ├── jadx/
│   ├── jadx.log
│   ├── apktool/
│   ├── apktool.log
│   └── trufflehog/
├── reports/
│   ├── <package>/<versionCode>/<sha256>/
│   │   ├── report.json
│   │   └── report.html
│   └── findings.csv
└── logs/apkworkbench.log
~~~

Do not commit the runtime workspace to Git. It contains original APKs, generated source, logs, and analysis output.

For another storage location:

~~~bash
export APKWORKBENCH_WORKSPACE="/path/to/APK-Workbench"
~~~

Persistent settings belong in **~/.config/apkworkbench/config.yaml**.

---

## 06 · Troubleshooting

### Inspect workspace state

~~~bash
apkworkbench status
tail -n 120 "$HOME/APK-Workbench/logs/apkworkbench.log"
~~~

### Locate per-artifact decompiler logs

~~~bash
find "$HOME/APK-Workbench/results" \
  -type f \( -name 'jadx.log' -o -name 'apktool.log' \) \
  -print
~~~

Each APK has separate JADX and Apktool logs. One decompiler's failure does not prevent the other from being attempted; the processing database records both statuses.

### Check external executables

~~~bash
command -v gpg
command -v java
command -v jadx
command -v apktool
command -v trufflehog

jadx --version
apktool --version
trufflehog --version
~~~

### Update the source checkout

~~~bash
cd "$HOME/apk-workbench"
git pull --ff-only
source .venv/bin/activate
python -m pip install -e ".[dev]"
~~~

Do not delete the runtime workspace as a routine troubleshooting step. It contains verified APKs, immutable manifests, and processing records.

---

## 07 · Security and integrity

- The signed F-Droid index is authenticated against a pinned OpenPGP primary fingerprint before parsing.
- APK downloads are checked against the index's expected size and SHA-256.
- SHA-256 is the unique binary identity.
- A frozen UUID manifest records every batch before its first download.
- Each APK is re-hashed before decompilation.
- JADX and Apktool run sequentially, with one worker/job.
- TruffleHog runs locally with credential verification disabled.
- Persisted findings contain allowlisted metadata and one-way fingerprints, not raw secret values.
- Reports are generated from sanitized findings.

These controls establish provenance and processing integrity; they do not prove that an APK is benign. APKs and generated output remain untrusted data. APK WORKBENCH performs static analysis and does not install or execute acquired APKs.

---

## 08 · Development checks

~~~bash
cd "$HOME/apk-workbench"
source .venv/bin/activate
python -m pytest
ruff check .
~~~

GitHub Actions tests Python 3.10, 3.11, and 3.12. Automated tests use generated local GPG keys and mocked network/subprocess boundaries. A green CI run is not a claim that a live F-Droid download or real local decompilation has been performed.

## Project documentation

- [Installation and First Run](docs/installation.md)
- [CLI Command Reference](docs/commands.md)
- [Configuration Reference](docs/configuration.md)
- [F-Droid Source Verification](docs/F-DROID-SOURCE-VERIFICATION.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [MIT License](LICENSE)

**APK WORKBENCH — CO-DEVELOPED BY dial9 + ChatGPT**  
**SLOW. SIMPLE. SEQUENTIAL. VERIFIED.**
- [Reliability and recovery](docs/reliability-and-recovery.md) — process isolation, retries, workspace locking, and per-run reconciliation.
