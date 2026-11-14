# Changelog

## Unreleased — Google Play Store acquisition

- Add explicit Play authentication modes (`sources.google_play.auth_mode`: `auto`/`account`/`anonymous`, default `auto`). `account` mode acquires sessions from the operator's own Google account via `goopdl auth login` or `GOOPDL_ACCOUNT_EMAIL`/`GOOPDL_AAS_TOKEN` and never contacts Aurora's dispenser; `anonymous` keeps the legacy dispenser-only path with its fail-closed account guarantee; `auto` prefers the account and falls back to the dispenser.
- Honor dispenser/token-source `retry_after` windows with a capped sleep before re-minting a Play session.
- `doctor` reports the resolved Play session source (masked account email included).
- Crash-safe discovery: the Google Play catalog is now a rolling union, persisted after every completed query/category channel, so a rate-limit abort mid-crawl keeps prior progress.
- Replace the swallowed `StopIteration` in `download` with an explicit bundle/plan mismatch error.
- Preserve base APKs, split APKs, and OBB expansion files in complete per-app bundle directories.
- Independently record and process every APK component; retain and verify OBB files without passing them to APK decompilers.
- Pin the upstream alpha `playstore-cli` client and document its unofficial API, free-app limitation, and account-restriction risk.
- Remove the former repository-source adapters, configuration, tests, and documentation.
