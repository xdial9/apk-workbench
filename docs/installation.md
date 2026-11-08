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

Install the external tools from their official instructions:

- JADX: https://github.com/skylot/jadx
- Apktool: https://github.com/iBotPeaches/Apktool
- TruffleHog: https://github.com/trufflesecurity/trufflehog

The workbench does not download or install these tools.

## 2. Clone and install the Google Play branch

```bash
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The package pins `playstore-cli==0.1.1` for the Play FDFE client and `goopdl==2.0.0` for anonymous session provisioning. Both are version-pinned because the adapter depends on their Python APIs; update either pin only with adapter and live-acquisition validation.

## 3. Configure anonymous Google Play access

No Google account, AAS token, API key, or browser sign-in is required. The adapter obtains short-lived anonymous device-session credentials from Aurora Store's public token dispenser on first use. The internal Play API still expects a bearer token, but the dispenser issues it without a user Google account.

```bash
apkworkbench doctor
```

Unset `GOOPDL_ACCOUNT_EMAIL` and `GOOPDL_AAS_TOKEN` if either is present; the adapter refuses to fall back to Google-account authentication. The anonymous token pool is cached under `~/.config/goopdl` by default. Set `GOOPDL_CONFIG_DIR` to move it.

The adapter communicates with Google's unofficial internal Play API. This is not an official Google API; service-side limits and terms may apply. The anonymous dispenser is a third-party service and may be rate-limited or unavailable. The current delivery path supports free apps only. Device profile compatibility affects which variants Google Play serves.

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

Automated tests mock the Google Play API, anonymous token provider, and download boundaries. They do not contact Aurora's live token dispenser or download a real app. Before a large corpus run, validate one representative app live and verify the resulting bundle, local hashes, decompilation, TruffleHog scan, and reconciliation.

## Anonymous token cache

Goopdl stores the short-lived anonymous token pool under `~/.config/goopdl` by default, using restrictive directory/file permissions. Set `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME` to relocate the cache. No Google account AAS token is stored or required. Do not share or commit the token-cache files.

The workbench workspace defaults to `~/APK-Workbench-Google-Play/`. Keep it separate from the Git checkout; it contains acquired APKs, OBBs, bundle metadata, processing results, reports, and logs.
