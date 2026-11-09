#!/usr/bin/env bash
# Phase One only: enumerate Google Play apps, acquire one complete bundle,
# independently verify every component on disk, and reconcile the run.
set -Eeuo pipefail
umask 077

query="${APKWORKBENCH_PHASE1_QUERY:-banking}"
category="${APKWORKBENCH_PHASE1_CATEGORY:-FINANCE}"
discovery_limit="${APKWORKBENCH_PHASE1_DISCOVERY_LIMIT:-30}"
apk_count="${APKWORKBENCH_PHASE1_APK_COUNT:-1}"

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

if ! command -v apkworkbench >/dev/null 2>&1; then
  echo "apkworkbench is not on PATH. Install the project in the active Python environment first." >&2
  exit 127
fi
if ! command -v python >/dev/null 2>&1; then
  echo "python is not on PATH." >&2
  exit 127
fi
if [[ -z "$query" ]]; then
  echo "APKWORKBENCH_PHASE1_QUERY must not be empty." >&2
  exit 2
fi
if [[ ! "$category" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "APKWORKBENCH_PHASE1_CATEGORY must be a Google Play category identifier." >&2
  exit 2
fi
if ! positive_integer "$discovery_limit" || ! positive_integer "$apk_count"; then
  echo "Discovery limit and APK count must be positive integers." >&2
  exit 2
fi

workspace="$(python -c 'from apkworkbench.core.config import Config; print(Config().get("workspace"))')"
mkdir -p "$workspace/logs"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_log="$workspace/logs/phase_one_${timestamp}.log"
download_log="$workspace/logs/phase_one_download_${timestamp}.log"
exec > >(tee -a "$run_log") 2>&1

catalog_path="$workspace/database/google_play_discovery.csv"
snapshot_dir="$workspace/database/discovery_snapshots"
mkdir -p "$snapshot_dir"
if [[ -L "$catalog_path" ]]; then
  echo "Refusing symlinked discovery catalog: $catalog_path" >&2
  exit 1
fi
if [[ -f "$catalog_path" ]]; then
  previous_snapshot="$snapshot_dir/google_play_discovery_before_"$timestamp"_"$BASHPID".csv"
  cp -p -- "$catalog_path" "$previous_snapshot"
  echo "Preserved previous discovery catalog: $previous_snapshot"
fi

echo "APK WORKBENCH — PHASE ONE"
echo "Started: $(date -u --iso-8601=seconds)"
echo "Workspace: $workspace"
echo "Discovery: category=$category query=$query limit=$discovery_limit"
echo "Acquisition target: $apk_count app(s)"
echo "Stages: DISCOVER -> DOWNLOAD -> VERIFY -> RECONCILE"
echo "Decompilers and scanners are not invoked in Phase One."
echo

apkworkbench discover \
  --category "$category" \
  --query "$query" \
  --limit "$discovery_limit" \
  --per-category "$discovery_limit" \
  --per-query "$discovery_limit"

if [[ ! -f "$catalog_path" || -L "$catalog_path" ]]; then
  echo "Discovery did not produce a regular package catalog: $catalog_path" >&2
  exit 1
fi
new_snapshot="$snapshot_dir/google_play_discovery_after_"$timestamp"_"$BASHPID".csv"
cp -p -- "$catalog_path" "$new_snapshot"
echo "Preserved this discovery catalog: $new_snapshot"

echo
echo "Starting acquisition..."
set +e
apkworkbench download --apk-count "$apk_count" 2>&1 | tee "$download_log"
download_status=${PIPESTATUS[0]}
set -e

run_id="$(sed -n 's/^Run ID: //p' "$download_log" | tail -n 1 | tr -d '\r')"
if [[ -z "$run_id" ]]; then
  echo "No acquisition run ID was emitted. No completed run manifest is available." >&2
  echo "Download exit status: $download_status" >&2
  echo "Download log: $download_log" >&2
  exit "${download_status:-1}"
fi

echo
echo "Independent on-disk verification: run $run_id"
set +e
apkworkbench verify-downloads --run-id "$run_id"
verify_status=$?

echo
echo "Reconciling immutable manifest and acquisition ledger..."
apkworkbench reconcile --run-id "$run_id"
reconcile_status=$?
set -e

if (( download_status != 0 )); then
  echo "Acquisition returned exit status $download_status." >&2
  exit "$download_status"
fi
if (( verify_status != 0 )); then
  echo "On-disk verification failed with exit status $verify_status." >&2
  exit "$verify_status"
fi
if (( reconcile_status != 0 )); then
  echo "Run reconciliation failed with exit status $reconcile_status." >&2
  exit "$reconcile_status"
fi

echo
echo "PHASE ONE COMPLETE"
echo "Run ID: $run_id"
echo "Download log: $download_log"
echo "Full run log: $run_log"
echo "Verified files are under: $workspace/downloads"
