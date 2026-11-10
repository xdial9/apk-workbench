# Security Policy

APK Workbench acquires Android application bundles from Google Play Store and performs local static analysis. It does not install or execute acquired apps.

## Acquisition provenance

- Google Play Store is the only configured acquisition source.
- The pinned upstream `playstore-cli` client verifies delivered APK components against Play-provided SHA-256 hashes and OBB files against Play-provided SHA-1 hashes.
- APK Workbench independently hashes each acquired file and records each APK component separately.
- Each bundle retains a JSON metadata record with package/version, component names, sizes, local hashes, Play-hash verification status, and available signing-certificate digests.
- Each APK is re-hashed before decompilation.

## Google account risk

The upstream client uses Google's unofficial internal Play API. It is an alpha research project, not an official Google API. Its use may violate Google's terms of service and may result in account restrictions. Use a dedicated research account, not a primary account.

The upstream client stores a long-lived AAS authentication token under `~/.config/playstore-cli` by default. Restrict filesystem permissions, back up only if necessary using encrypted storage, and never commit or share account/device/session files. Do not paste credentials, cookies, or tokens into ChatGPT, issues, logs, or pull requests.

## Untrusted inputs

Treat APKs, OBBs, generated source, decompiler output, and scanner output as untrusted. Keep Apktool and TruffleHog current. Do not install acquired APKs on a production device.

## Reporting a vulnerability

Do not include live credentials, private APKs, or raw secret values in a public issue. Report a minimal reproduction and sanitized logs through the repository's private reporting channel when available.
