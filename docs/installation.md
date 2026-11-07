# Installation and first run

This guide is the supported, copy-and-paste installation path for Debian 13 and Ubuntu 22.04/24.04 on 64-bit Linux. Other distributions may work, but their package names and system paths are not covered here.

APK WORKBENCH itself is Python. JADX, Apktool, TruffleHog, Java, and GnuPG are separate system tools; installing the Python package does not install those tools.

## 1. Install system prerequisites

Open a terminal and run:

```bash
sudo apt update
sudo apt install -y \
  ca-certificates \
  git \
  curl \
  unzip \
  gnupg \
  python3 \
  python3-venv \
  python3-pip \
  default-jre-headless
```

Confirm Python and Java:

```bash
python3 --version
java -version
gpg --version
```

Python must be 3.10 or newer. JADX 1.5.6 requires 64-bit Java 11 or newer. The distribution's default Java runtime is used; confirm its version with `java -version`.

## 2. Install JADX

Download and install the published JADX 1.5.6 command-line distribution:

```bash
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
```

Add the user-local binary directory to PATH for future terminal sessions:

```bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.profile" || \
  printf '\n# User-installed command-line tools\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.profile"
export PATH="$HOME/.local/bin:$PATH"
```

Check:

```bash
jadx --version
```

If the release URL or asset name changes in a future JADX release, use the official release page and update the version and filename in these commands: https://github.com/skylot/jadx/releases

## 3. Install Apktool

Download the official Apktool 3.0.3 JAR into the user-local tools directory:

```bash
mkdir -p "$HOME/.local/opt/apktool-3.0.3" "$HOME/.local/bin"
curl -fL --retry 3 \
  -o "$HOME/.local/opt/apktool-3.0.3/apktool.jar" \
  https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar
printf '%s  %s\n' \
  'dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423' \
  "$HOME/.local/opt/apktool-3.0.3/apktool.jar" | sha256sum -c -
```

The SHA-256 value above is published in the Apktool 3.0.3 release notes. Stop if the checksum does not match.

Create a small PATH wrapper that invokes the JAR explicitly:

```bash
cat > "$HOME/.local/bin/apktool" <<'EOF'
#!/bin/sh
exec java -jar "$HOME/.local/opt/apktool-3.0.3/apktool.jar" "$@"
EOF
chmod 0755 "$HOME/.local/bin/apktool"
```

Check:

```bash
apktool --version
```

Official installation and release references:
- https://apktool.org/docs/
- https://github.com/iBotPeaches/Apktool/releases

## 4. Install TruffleHog

Install the official Truffle Security release installer into `/usr/local/bin`:

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | \
  sudo sh -s -- -b /usr/local/bin
```

Check:

```bash
trufflehog --version
```

The project checks the installed TruffleHog help output before scanning. The installed build must support the filesystem scanner and the flags `--no-verification`, `--no-update`, `--json`, `--concurrency`, and `--fail-on-scan-errors`. If it does not, APK WORKBENCH will stop the scan rather than silently run with different security behavior.

TruffleHog's installer supports signature verification with its `-v` option when Cosign is installed. See the official installation and verification instructions: https://github.com/trufflesecurity/trufflehog

## 5. Clone APK WORKBENCH

Use the ordinary clone command:

```bash
cd "$HOME"
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench
```

The repository's default branch is intended to contain the complete supported project. If GitHub currently still defaults to the placeholder `main` branch, use the temporary explicit branch command below until the default-branch change is complete:

```bash
git clone --branch chatgpt/bootstrap https://github.com/xdial9/apk-workbench.git
cd apk-workbench
```

## 6. Install the Python application

Run these commands from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

This installs APK WORKBENCH and its Python dependencies into the project virtual environment. It does not modify the operating system's Python packages.

Confirm the CLI is installed:

```bash
apkworkbench version
```

## 7. Run the environment check

Keep the virtual environment active and run:

```bash
apkworkbench doctor
```

All five required executables must show `[OK]`:

- `gpg`
- `java`
- `jadx`
- `apktool`
- `trufflehog`

If any item is `[MISSING]`, install that executable or correct its PATH. If it is `[UNHEALTHY]`, run its version command directly and resolve that error before proceeding.

## 8. Verify F-Droid discovery without downloading APKs

Run:

```bash
apkworkbench discover --limit 20
```

This retrieves the F-Droid repository index and detached signature, checks the pinned OpenPGP primary fingerprint, verifies the signature, and only then parses the index. A successful result must explicitly report:

```text
Index signature: VERIFIED
```

If signature verification fails, stop. Do not remove or weaken the fingerprint pin to get past the error.

## 9. Acquire and process a small batch

The first acquisition writes the workspace database and a frozen run manifest before downloading. It downloads only new unique APK SHA-256 artifacts and validates both the expected size and digest before publishing each APK.

Start with three APKs:

```bash
apkworkbench download --apk-count 3
```

Then run the processing stages:

```bash
apkworkbench decompile --limit 3
apkworkbench analyze --limit 3
apkworkbench report
apkworkbench status
```

After inspecting the results, you can run the complete pipeline for ten new APKs:

```bash
apkworkbench run --apk-count 10
```

The pipeline runs sequentially. It does not run multiple APK downloads, decompilers, or scanner jobs concurrently.

## 10. Where the data goes

The source checkout and runtime data are separate. By default, runtime data is stored in:

```text
~/APK-Workbench/
```

The workspace contains the original APKs, append-only acquisition records, frozen manifests, decompilation outputs, scan output, sanitized reports, and logs. Do not commit this workspace to Git.

For a different disk or mount point, set `workspace` in `~/.config/apkworkbench/config.yaml`, or export:

```bash
export APKWORKBENCH_WORKSPACE="/path/to/APK-Workbench"
```

See [configuration.md](configuration.md) for all supported configuration keys and environment overrides.

## 11. Tests and development checks

From the repository root, with the virtual environment active:

```bash
python -m pytest
ruff check .
```

CI runs the test suite on Python 3.10, 3.11, and 3.12. The tests use generated local GPG keys and mocked network and subprocess behavior; CI does not claim to perform a live F-Droid acquisition or a real TruffleHog scan.

## Troubleshooting

### `python3 -m venv .venv` fails

Install the matching distro venv package:

```bash
sudo apt install -y python3-venv
```

Then remove the incomplete environment and retry:

```bash
rm -rf .venv
python3 -m venv .venv
```

### `apkworkbench: command not found`

Activate the environment from the repository root:

```bash
source .venv/bin/activate
```

If the environment was not created, repeat Step 6.

### `jadx`, `apktool`, or `trufflehog` is missing

Check the command and PATH:

```bash
printf '%s\n' "$PATH"
command -v jadx
command -v apktool
command -v trufflehog
```

For JADX and Apktool, confirm `$HOME/.local/bin` is in PATH. For TruffleHog, confirm `/usr/local/bin` is in PATH.

### TruffleHog refuses to scan because a required option is unavailable

Do not bypass the compatibility check. Update TruffleHog from its official release installer, then run:

```bash
trufflehog filesystem --help
apkworkbench doctor
```

### F-Droid signature verification fails

Check system time and network access, then retry discovery. Do not replace the configured signer fingerprint based on an error message. The configured fingerprint is a trust anchor and must only be changed after independent confirmation from F-Droid's official signing-key documentation.

### A download fails its size or SHA-256 check

The artifact is not published as a completed APK and is not added to successful download history. Review the attempt record and application log, then retry discovery/acquisition after checking connectivity and available disk space.
