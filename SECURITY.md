# Security Policy

APK Workbench acquires Android application bundles from Google Play Store and performs local static analysis. It does not install or execute acquired apps.

## Acquisition provenance

- Google Play Store is the only configured acquisition source.
- The pinned upstream `playstore-cli` client verifies delivered APK components against Play-provided SHA-256 hashes and OBB files against Play-provided SHA-1 hashes.
- APK Workbench independently hashes each acquired file and records each APK component separately.
- Each bundle retains a JSON metadata record with package/version, component names, sizes, local hashes, Play-hash verification status, and available signing-certificate digests.
- Each APK is re-hashed before decompilation.

## Anonymous Play session risk

The adapter uses Google's unofficial internal Play API. It is not an official Google API, and its use may be subject to Google's terms and service-side restrictions. No user Google account or long-lived AAS token is required. Instead, goopdl obtains short-lived anonymous bearer tokens from Aurora Store's public token dispenser. Aurora is a third-party service, not Google; its dispenser may change, rate-limit requests, or become unavailable.

Goopdl caches anonymous tokens under `~/.config/goopdl` by default with restrictive directory/file permissions. Treat this cache as credential material: do not commit, share, or include it in archives. Set `GOOPDL_CONFIG_DIR` or `XDG_CONFIG_HOME` to relocate the cache. APK Workbench refuses to fall back to Google-account mode when `GOOPDL_ACCOUNT_EMAIL` or `GOOPDL_AAS_TOKEN` is set.

## Untrusted inputs

Treat APKs, OBBs, generated source, decompiler output, and scanner output as untrusted. Keep JADX, Apktool, and TruffleHog current. Do not install acquired APKs on a production device.

## Reporting a vulnerability

Do not include live credentials, private APKs, or raw secret values in a public issue. Report a minimal reproduction and sanitized logs through the repository's private reporting channel when available.
