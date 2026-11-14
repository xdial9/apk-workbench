# Security Policy

APK Workbench acquires Android application bundles from Google Play Store and performs local static analysis. It does not install or execute acquired apps.

## Acquisition provenance

- Google Play Store is the only configured acquisition source.
- The pinned upstream `playstore-cli` client verifies delivered APK components against Play-provided SHA-256 hashes and OBB files against Play-provided SHA-1 hashes.
- APK Workbench independently hashes each acquired file and records each APK component separately.
- Each bundle retains a JSON metadata record with package/version, component names, sizes, local hashes, Play-hash verification status, and available signing-certificate digests.
- Each APK is re-hashed before decompilation.

## Session modes and service risk

The adapter uses Google's unofficial internal Play API through `playstore-cli`; goopdl supplies Play device-session credentials in one of three modes (`sources.google_play.auth_mode`). **Anonymous mode** obtains them from Aurora Store's public token dispenser — not Google; it may rate-limit or become unavailable. **Account mode** authenticates with an operator-chosen Google account against Google's Android setup endpoint, and never contacts the dispenser. `auto` (the default) prefers the account when one is configured. Google may also change or restrict the internal Play protocol.

Anonymous operation by default avoids a personal Google account, AAS token, or user-supplied bearer token. goopdl caches short-lived bearer/device credentials under `~/.config/goopdl` by default. Restrict filesystem permissions and never commit or share these files. In `anonymous` mode the adapter fails closed when `GOOPDL_ACCOUNT_EMAIL` or `GOOPDL_AAS_TOKEN` is set rather than silently entering account mode. Never paste credentials, cookies, tokens, or session files into ChatGPT, issues, logs, or pull requests.

Play may add a free app to the selected device profile's library as part of delivery acquisition — in account mode that profile belongs to your own account, so use a dedicated account for automation. Device profile compatibility affects which APK variants are served.

## Untrusted inputs

Treat APKs, OBBs, generated source, decompiler output, and scanner output as untrusted. Keep Apktool and TruffleHog current. Do not install acquired APKs on a production device.

## Reporting a vulnerability

Do not include live credentials, private APKs, or raw secret values in a public issue. Report a minimal reproduction and sanitized logs through the repository's private reporting channel when available.
