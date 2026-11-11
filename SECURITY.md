# Security Policy

APK Workbench acquires Android application bundles from Google Play Store and performs local static analysis. It does not install or execute acquired apps.

## Acquisition provenance

- Google Play Store is the only configured acquisition source.
- The pinned upstream `playstore-cli` client verifies delivered APK components against Play-provided SHA-256 hashes and OBB files against Play-provided SHA-1 hashes.
- APK Workbench independently hashes each acquired file and records each APK component separately.
- Each bundle retains a JSON metadata record with package/version, component names, sizes, local hashes, Play-hash verification status, and available signing-certificate digests.
- Each APK is re-hashed before decompilation.

## Anonymous session and service risk

The adapter uses Google's unofficial internal Play API through `playstore-cli`, and anonymous session credentials from goopdl's integration with Aurora Store's public token dispenser. Neither is an official Google API/service. The dispenser is a third-party service; it may rate-limit or become unavailable. Google may also change or restrict the internal Play protocol.

Normal APK Workbench operation does not use a personal Google account, AAS token, or user-supplied bearer token. goopdl caches short-lived anonymous bearer/device credentials under `~/.config/goopdl` by default. Restrict filesystem permissions and never commit or share these files. The adapter fails closed when `GOOPDL_ACCOUNT_EMAIL` or `GOOPDL_AAS_TOKEN` is set, rather than silently entering account mode. Do not paste credentials, cookies, anonymous tokens, or session files into ChatGPT, issues, logs, or pull requests.

Play may add a free app to the anonymous device profile's library as part of delivery acquisition. Device profile compatibility affects which APK variants are served.

## Untrusted inputs

Treat APKs, OBBs, generated source, decompiler output, and scanner output as untrusted. Keep Apktool and TruffleHog current. Do not install acquired APKs on a production device.

## Reporting a vulnerability

Do not include live credentials, private APKs, or raw secret values in a public issue. Report a minimal reproduction and sanitized logs through the repository's private reporting channel when available.
