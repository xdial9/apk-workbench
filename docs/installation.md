![APK WORKBENCH](assets/apk-workbench-banner.svg)

# Installation & First Run

**Supported target:** 64-bit Debian 13 and Ubuntu 22.04/24.04  
**Application runtime:** Python 3.10+  
**Execution model:** local CLI · verified inputs · persistent records

This guide installs the external tools, creates an isolated Python environment, and runs an authenticated batch. Java, GnuPG, JADX, Apktool, and TruffleHog are system dependencies; pip does not install them.

## 1. Install system prerequisites

```bash
sudo apt update
sudo apt install -y ca-certificates git curl unzip gnupg python3 python3-venv python3-pip default-jre-headless
```

Python 3.10 or newer and a 64-bit Java 11-or-newer runtime are required.

## 2. Install JADX 1.5.6

```bash
mkdir -p "$HOME/.local/opt" "$HOME/.local/bin"
cd /tmp
curl -fL --retry 3 -o jadx-1.5.6.zip \
  https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip
unzip -q -o jadx-1.5.6.zip -d "$HOME/.local/opt/jadx-1.5.6"
cat > "$HOME/.local/bin/jadx" <<'EOF'
#!/bin/sh
exec "$HOME/.local/opt/jadx-1.5.6/bin/jadx" "$@"
EOF
chmod 0755 "$HOME/.local/bin/jadx"
```

## 3. Install Apktool 3.0.3

```bash
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
```

The checksum must report **OK**. Stop if it does not.

## 4. Install TruffleHog and set PATH

```bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.profile" || \
  printf '\n# APK WORKBENCH user-local tools\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.profile"
export PATH="$HOME/.local/bin:$PATH"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | \
  sudo sh -s -- -b /usr/local/bin
trufflehog --version
```

APK WORKBENCH checks that TruffleHog's filesystem command advertises `--results`, `--no-update`, `--json`, `--concurrency`, and `--fail-on-scan-errors`. Scans are invoked with `--results=verified`; unverified findings are rejected. Do not add a flag that disables credential verification.

## 5. Clone and install APK WORKBENCH

```bash
cd "$HOME"
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
apkworkbench doctor
```

GnuPG, Java, JADX, Apktool, and TruffleHog must all report **[OK]**.

## 6. Run a batch

```bash
apkworkbench discover --limit 20
apkworkbench run --apk-count 3
apkworkbench status
```

Discovery authenticates the F-Droid index signature against the configured pinned OpenPGP fingerprint before parsing metadata. The pipeline freezes a manifest before downloads, validates APK size and SHA-256, re-hashes APKs before decompilation, and requests verified-only TruffleHog findings.

To run individual stages, use the Run ID printed by `download`:

```bash
apkworkbench download --apk-count 3
apkworkbench decompile --run-id YOUR-RUN-ID
apkworkbench analyze --run-id YOUR-RUN-ID
apkworkbench report
```

## Workspace and checks

Runtime data is stored separately from the source checkout, by default under `~/APK-Workbench/`. Do not commit APKs, generated source, findings, or runtime data to Git. See [Configuration](configuration.md) for workspace and timeout settings.

For development checks:

```bash
python -m pytest
ruff check .
```

Automated tests mock external tool and network boundaries; passing tests do not claim a live APK end-to-end validation.

## Troubleshooting

Use `apkworkbench status` and inspect `~/APK-Workbench/logs/apkworkbench.log` and the per-artifact `jadx.log` / `apktool.log` files. A download that fails size or SHA-256 validation is not published as a verified APK; never manually add an unverified APK to acquisition history.

Official TruffleHog information: https://github.com/trufflesecurity/trufflehog
