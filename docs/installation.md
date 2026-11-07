![APK WORKBENCH](assets/apk-workbench-banner.svg)

# Installation & First Run

**Supported target:** 64-bit Debian 13 and Ubuntu 22.04/24.04  
**Application runtime:** Python 3.10+  
**Execution model:** local CLI · sequential tools · verified APK inputs

This guide installs the external tools, creates an isolated Python virtual environment, verifies the toolchain, and runs a first authenticated batch.

> APK WORKBENCH is a Python application. Java, GnuPG, JADX, Apktool, and TruffleHog are separate system dependencies; pip does not install them.

---

## 01 · System prerequisites

~~~bash
sudo apt update
sudo apt install -y \
  ca-certificates git curl unzip gnupg \
  python3 python3-venv python3-pip default-jre-headless

python3 --version
java -version
gpg --version
~~~

Python must be 3.10 or newer. JADX 1.5.6 requires a 64-bit Java 11-or-newer runtime.

## 02 · Install JADX 1.5.6

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

Official release page: https://github.com/skylot/jadx/releases

## 03 · Install Apktool 3.0.3

~~~bash
mkdir -p "$HOME/.local/opt/apktool-3.0.3" "$HOME/.local/bin"

curl -fL --retry 3 \
  -o "$HOME/.local/opt/apktool-3.0.3/apktool.jar" \
  https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar

printf '%s  %s\n' \
  'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423' \
  "$HOME/.local/opt/apktool-3.0.3/apktool.jar" | sha256sum -c -
~~~

The expected checksum is pinned in this installation procedure. The result must end with **OK**. Stop if verification fails.

~~~bash
cat > "$HOME/.local/bin/apktool" <<'EOF'
#!/bin/sh
exec java -jar "$HOME/.local/opt/apktool-3.0.3/apktool.jar" "$@"
EOF
chmod 0755 "$HOME/.local/bin/apktool"
~~~

Official references:
- https://apktool.org/docs/
- https://github.com/iBotPeaches/Apktool/releases

## 04 · Add user-local tools to PATH

~~~bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.profile" || \
  printf '\n# APK WORKBENCH user-local tools\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.profile"

export PATH="$HOME/.local/bin:$PATH"
~~~

The final export updates the current shell. The profile entry applies to future login sessions.

## 05 · Install TruffleHog

~~~bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | \
  sudo sh -s -- -b /usr/local/bin

trufflehog --version
~~~

APK WORKBENCH requires the TruffleHog filesystem command to advertise:

- **--no-verification**
- **--no-update**
- **--json**
- **--concurrency**
- **--fail-on-scan-errors**

The application checks these capabilities before scanning and refuses to continue if the required behavior cannot be confirmed. Do not bypass the compatibility check.

Official installation and verification: https://github.com/trufflesecurity/trufflehog

## 06 · Clone the repository

~~~bash
cd "$HOME"
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench
~~~

The default branch is **main**. A standard clone is sufficient.

## 07 · Create the Python environment

Run from the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

apkworkbench version
~~~

Keep the virtual environment active when running the application and development checks. Using **python -m pip** with the environment activated installs Python packages inside that environment rather than the operating system's Python installation.

## 08 · Verify external dependencies

~~~bash
apkworkbench doctor
~~~

These five executables must report **[OK]**:

- gpg
- java
- jadx
- apktool
- trufflehog

A **[MISSING]** result means the executable is not on PATH. An **[UNHEALTHY]** result means its version command did not complete successfully. Resolve those issues before continuing.

## 09 · Authenticate F-Droid discovery

~~~bash
apkworkbench discover --limit 20
~~~

Successful output includes:

~~~text
Index signature: VERIFIED
~~~

The repository client retrieves the pinned signing key, signed index, and detached signature. It checks the imported primary fingerprint and verifies the detached signature before parsing JSON.

The signed index and detached signature are cached under **~/.local/state/apkworkbench/fdroid-cache/** for six hours by default. The signature is re-verified every time cached data is used. To bypass the cache and retrieve a fresh signed copy, run:

~~~bash
apkworkbench discover --refresh-index
~~~

The CLI reports the retrieval phase and index byte counts. Signature failures are fatal. Do not remove or weaken the fingerprint pin.

## 10 · Run the first end-to-end batch

Start with three newly selected APK binaries:

~~~bash
apkworkbench run --apk-count 3
apkworkbench status
~~~

The run command handles the complete pipeline. It freezes a manifest before the first download and passes that manifest's run ID to decompilation and analysis. Older workspace downloads are not mixed into the new batch.

### Separate stage workflow

The download command also works on its own:

~~~bash
apkworkbench download --apk-count 3
~~~

Copy the UUID printed as **Run ID**, then scope the processing stages explicitly:

~~~bash
apkworkbench decompile --run-id YOUR-RUN-ID
apkworkbench analyze --run-id YOUR-RUN-ID
apkworkbench report
apkworkbench status
~~~

Without **--run-id**, standalone decompile and analyze commands intentionally consider eligible artifacts throughout the workspace.

## 11 · Runtime workspace and storage

Default location:

~~~text
~/APK-Workbench/
~~~

The workspace stores original APKs, immutable run manifests, append-only acquisition records, processing status, decompiler output, scan output, sanitized reports, and logs.

The source checkout can be updated or recloned without deleting runtime data. Do not commit the runtime workspace to Git.

For a different storage location:

~~~bash
export APKWORKBENCH_WORKSPACE="/path/to/APK-Workbench"
~~~

For a persistent setting, configure **workspace** in **~/.config/apkworkbench/config.yaml**. See [Configuration](configuration.md).

## 12 · Development checks

~~~bash
cd "$HOME/apk-workbench"
source .venv/bin/activate

python -m pytest
ruff check .
~~~

GitHub Actions tests Python 3.10, 3.11, and 3.12. Automated tests use generated local GPG keys and mocked network/subprocess behavior. A passing CI run does not claim live F-Droid retrieval or real external APK tool execution.

---

## Troubleshooting

### The virtual environment cannot be created

~~~bash
sudo apt install -y python3-venv
python3 -m venv .venv
~~~

If an incomplete environment prevents recreation, remove only that **.venv** directory from the repository root and try again.

### The CLI is not found

~~~bash
cd "$HOME/apk-workbench"
source .venv/bin/activate
python -m pip install -e ".[dev]"
~~~

### An external tool is missing from PATH

~~~bash
printf '%s\n' "$PATH"
command -v gpg
command -v java
command -v jadx
command -v apktool
command -v trufflehog
~~~

For JADX and Apktool, confirm **$HOME/.local/bin** is on PATH. For TruffleHog, confirm **/usr/local/bin** is on PATH.

### F-Droid retrieval appears idle

The client reports its current phase and index byte counts. Inspect the most recent application log:

~~~bash
tail -n 120 "$HOME/APK-Workbench/logs/apkworkbench.log"
~~~

The index must authenticate successfully before index metadata is trusted.

### Inspect decompilation errors

~~~bash
apkworkbench status

find "$HOME/APK-Workbench/results" \
  -type f \( -name 'jadx.log' -o -name 'apktool.log' \) \
  -print
~~~

Each APK has separate JADX and Apktool logs. Review tool exit codes and captured output before deciding whether a retry is appropriate.

### A download fails integrity verification

A failed size or SHA-256 check prevents the temporary download from being published as a verified APK. Review **database/download_attempts.csv** and **logs/apkworkbench.log**. Never manually add an unverified APK to the download history.
