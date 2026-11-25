# Changelog

## 0.3.0 — 2026-11-24

- Package APK Workbench for PyPI as `apkworkbench` (`pip install apkworkbench`), version `0.3.0`, bundling AI handoff prompts (`0.txt`–`6.txt`), the default config template, `README.md`, and the MIT `LICENSE` in both wheel and sdist distributions.
- Consolidate the workspace into a single-folder home layout at `~/APK-Workbench` (overridable via `APKWORKBENCH_WORKSPACE` or `--workspace`), unifying config, state, logs, and runs in one directory instead of splitting across `~/.config/apkworkbench` and `~/.local/state/apkworkbench`, while preserving backward-compatible fallback for legacy `~/.config/apkworkbench/config.yaml`.
- Introduce self-contained per-run folders (`~/APK-Workbench/runs/<package>-v<version>-<run_id>/`) holding APK(s), Apktool decode (eliminating duplicate apktool directories), surface analysis, TruffleHog findings, manifest, reports, stages, logs, prompts, hashes, `README.md`, and `ai_analysis/`, indexed by a single `runs_index.json`.
- Add local APK self-contained pipeline execution (`apkworkbench run --local-apk <path>`) and a workspace migration tool (`apkworkbench migrate` / `scripts/migrate_workspace.py` with `--dry-run` and `--apply`).
- Enhance `apkworkbench doctor` to report external system tools (`java`, `apktool`, `trufflehog`, `playstore-cli`, `androguard`), workspace home health, bundled prompts, and Google Play auth status, with actionable install hints when a required system tool is missing at runtime.

## 0.2.0 — Google Play Store acquisition

- Add explicit Play authentication modes (`sources.google_play.auth_mode`: `auto`/`account`/`anonymous`, default `auto`). `account` mode acquires sessions from the operator's own Google account via `goopdl auth login` or `GOOPDL_ACCOUNT_EMAIL`/`GOOPDL_AAS_TOKEN` and never contacts Aurora's dispenser; `anonymous` keeps the legacy dispenser-only path with its fail-closed account guarantee; `auto` prefers the account and falls back to the dispenser.
- Honor dispenser/token-source `retry_after` windows with a capped sleep before re-minting a Play session.
- `doctor` reports the resolved Play session source (masked account email included).
- Crash-safe discovery: the Google Play catalog is now a rolling union, persisted after every completed query/category channel, so a rate-limit abort mid-crawl keeps prior progress.
- Replace the swallowed `StopIteration` in `download` with an explicit bundle/plan mismatch error.
- Preserve base APKs, split APKs, and OBB expansion files in complete per-app bundle directories.
- Independently record and process every APK component; retain and verify OBB files without passing them to APK decompilers.
- Pin the upstream alpha `playstore-cli` client and document its unofficial API, free-app limitation, and account-restriction risk.
- Remove the former repository-source adapters, configuration, tests, and documentation.
