# Installation and First Run

**Target:** 64-bit Debian or Ubuntu  
**Python:** 3.10+  
**External tools:** Java 11+, Apktool, TruffleHog  
**Acquisition:** Google Play Store only

## 1. System prerequisites

```bash
sudo apt update
sudo apt install -y ca-certificates git curl unzip python3 python3-venv python3-pip default-jre-headless
python3 --version
java -version
```

Install the external tools from their official instructions:

- Apktool: https://github.com/iBotPeaches/Apktool
- TruffleHog: https://github.com/trufflesecurity/trufflehog

The workbench does not download or install these tools.

## 2. Clone and install the Apktool-only validation branch

```bash
git clone --branch fix/apktool-only-trufflehog-pipeline https://github.com/xdial9/apk-workbench.git
cd apk-workbench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The package pins `playstore-cli==0.1.1` for Play API/delivery operations and `goopdl==2.0.0` for anonymous sessions. Both are used through their Python APIs. `playstore-cli` is an unofficial research client for Google's internal Play API; pin changes require adapter tests and live-acquisition validation.

## 3. Configure anonymous Google Play access

```bash
source .venv/bin/activate
apkworkbench doctor
```

No Google login, AAS token, API key, browser sign-in, or manually supplied bearer token is required. On the first Play request, goopdl obtains short-lived anonymous credentials from Aurora Store's public token dispenser and maintains a rotating local token pool. The Play API still uses a bearer token internally, but it is issued anonymously rather than from your Google account. The dispenser is a third-party service and may rate-limit or become unavailable; the Play API itself is unofficial. The adapter currently targets free apps, and Play may add a free app to the anonymous device profile's library as part of delivery. Device profile compatibility affects which variants are served.

Unset `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` if either is present. APK Workbench fails closed rather than using Google account credentials.

## 4. Verify dependencies

```bash
apkworkbench doctor
```

The required executables are `playstore-cli`, `java`, `apktool`, and `trufflehog`.

## 5. Discover and acquire a small sample

```bash
apkworkbench discover --limit 100 --category FINANCE
apkworkbench download --apk-count 3
apkworkbench status
```

Or run the full pipeline:

```bash
apkworkbench run --apk-count 3
```

A Google Play app can contain a base APK, split APKs, and OBB expansion files. All bundle components are preserved. Each APK component is recorded separately for Apktool decoding and static analysis; OBB files are retained and integrity-checked but are not passed to Apktool.

## 6. Development checks

```bash
python -m pytest
ruff check .
```

Automated tests mock the anonymous dispenser, Google Play API, delivery, and download boundaries. They do not prove the live dispenser is available or download a real app. Before a large corpus run, validate one representative app live and verify the resulting bundle, local hashes, Apktool decoding, TruffleHog scan, and reconciliation.

## Anonymous token cache and storage

The anonymous goopdl token cache defaults to `~/.config/goopdl`. Set `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME` to relocate it. On POSIX, goopdl creates the directory with mode `0700` and token files with mode `0600`. These are short-lived anonymous bearer/device credentials; keep the directory private and never commit or share it. APK Workbench does not read saved `playstore-cli` account credentials.

The workbench workspace defaults to `~/APK-Workbench/workspace/`, keeping runtime data alongside the code in a single checkout-rooted directory.
