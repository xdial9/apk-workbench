# Installation and First Run

**Target:** 64-bit Debian or Ubuntu  
**Python:** 3.10+  
**External tools:** Java 11+, JADX, Apktool, TruffleHog  
**Acquisition:** Google Play Store only

## 1. System prerequisites

```bash
sudo apt update
sudo apt install -y ca-certificates git curl unzip python3 python3-venv python3-pip default-jre-headless
python3 --version
java -version
```

Install the external tools from their official instructions:\n\n- JADX: https://github.com/skylot/jadx\n- Apktool: https://github.com/iBotPeaches/Apktool\n- TruffleHog: https://github.com/trufflesecurity/trufflehog\n\nThe workbench does not download or install these tools.

## 2. Clone and install the Google Play branch

```bash
git clone --branch fix/google-play-acquisition https://github.com/xdial9/apk-workbench.git
cd apk-workbench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The package pins `playstore-cli==0.1.1`. Its API is alpha and may change; update the pin only with adapter and live-acquisition validation.

## 3. Authenticate with Google Play

```bash
playstore-cli login
playstore-cli checkin
```

Complete sign-in in the browser on your own machine. Use a separate research Google account. Do not paste credentials, cookies, or tokens into chat or source control.

The upstream client communicates with Google's unofficial internal Play API. Google may restrict the account; this is an explicit operational risk. The client currently supports downloading free apps only. A free app that is not already in the research account's Play library may be added to that account as part of delivery acquisition. Review this account-side effect before using the research account. Device profile compatibility affects which variants Google Play serves.

## 4. Verify dependencies

```bash
apkworkbench doctor
```

The required executables are `playstore-cli`, `java`, `jadx`, `apktool`, and `trufflehog`.

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

A Google Play app can contain a base APK, split APKs, and OBB expansion files. All bundle components are preserved. Each APK component is recorded separately for decompilation and static analysis; OBB files are retained but not decompiled.

## 6. Development checks

```bash
python -m pytest
ruff check .
```

Automated tests mock Google Play API and download boundaries. They do not authenticate a real account or download a real app. Before a large corpus run, validate one representative app live and verify the resulting bundle, local hashes, decompilation, TruffleHog scan, and reconciliation.

## Credentials and storage

The upstream client stores its account token and device/session state in `~/.config/playstore-cli` by default. Restrict access to that directory. The `PLAYSTORE_HOME` environment variable can relocate it.

The workbench workspace defaults to `~/APK-Workbench/`. Keep it separate from the Git checkout; it contains acquired APKs, OBBs, bundle metadata, processing results, reports, and logs.
