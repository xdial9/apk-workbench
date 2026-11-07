# Command Reference

Run commands from a terminal with the APK WORKBENCH virtual environment activated.

## Global help and version

```bash
apkworkbench --help
apkworkbench version
```

## doctor

Check that all required external programs can be found and that their version commands succeed:

```bash
apkworkbench doctor
```

Required: `gpg`, `java`, `jadx`, `apktool`, and `trufflehog`. The command exits non-zero if a required dependency is missing or unhealthy.

## discover

Authenticate the F-Droid repository index and display the latest indexed version for each package:

```bash
apkworkbench discover
apkworkbench discover --limit 50
apkworkbench discover --package org.example.app
```

Options:

- `--limit INTEGER`: maximum number of package records to display (default: 20; zero displays none).
- `--package TEXT`: exact Android application ID filter.

This command does not download APK files.

## download

Select and acquire new, unique APK binaries:

```bash
apkworkbench download
apkworkbench download --apk-count 3
apkworkbench download --apk-count 5 --package org.example.app
```

Options:

- `--apk-count INTEGER`: requested number of new unique binaries (default: 10; minimum: 1).
- `--package TEXT`: restrict selection to one exact Android application ID.

Previously acquired SHA-256 hashes are excluded. A run manifest is frozen before downloads begin. A shortfall is reported when fewer new unique artifacts are available than requested.

## decompile

Run JADX and then Apktool sequentially for acquired APKs whose recorded SHA-256 and size still match:

```bash
apkworkbench decompile
apkworkbench decompile --limit 3
apkworkbench decompile --force
```

Options:

- `--limit INTEGER`: maximum number of APKs to process (default: 0, meaning all eligible APKs).
- `--force`: repeat work even if both decompilers previously succeeded.

Use `--force` only when intentionally repeating completed work.

## analyze

Run local TruffleHog filesystem scans on successfully decompiled artifacts:

```bash
apkworkbench analyze
apkworkbench analyze --limit 3
apkworkbench analyze --force
```

Options:

- `--limit INTEGER`: maximum number of eligible APKs to scan (default: 0, meaning all).
- `--force`: repeat scans that previously succeeded.

Credential verification is disabled. The application validates the installed TruffleHog CLI options before scanning and fails closed if it cannot establish the required no-verification behavior.

## report

Generate per-artifact JSON and HTML reports plus the aggregate sanitized findings CSV:

```bash
apkworkbench report
```

No options.

## status

Display acquisition, decompilation, and scan totals:

```bash
apkworkbench status
```

No options.

## run

Execute download, decompilation, analysis, and reporting in sequence:

```bash
apkworkbench run
apkworkbench run --apk-count 3
apkworkbench run --apk-count 10 --package org.example.app
apkworkbench run --force-decompile --force-analyze
```

Options:

- `--apk-count INTEGER`: requested number of new unique APK binaries (default: 10; minimum: 1).
- `--package TEXT`: restrict acquisition to one exact package ID.
- `--force-decompile`: repeat completed decompilation work.
- `--force-analyze`: repeat successful TruffleHog scans.

The pipeline continues to later stages when a stage reports a non-zero exit, then returns a non-zero final status if any stage needed attention. Review the stage output, `apkworkbench status`, and per-artifact logs.

## Exit status

- `0`: command completed without a reported error.
- `1`: command failed or one or more pipeline stages need attention.
- `2`: acquisition completed its selection logic but could not meet the requested APK count because of a shortfall.

## Typical daily workflow

```bash
source .venv/bin/activate
apkworkbench doctor
apkworkbench discover --limit 20
apkworkbench run --apk-count 10
apkworkbench status
```
