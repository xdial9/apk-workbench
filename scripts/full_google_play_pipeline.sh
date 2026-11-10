#!/usr/bin/env bash
# End-to-end Google Play acquisition and Apktool -> TruffleHog processing.
# TruffleHog is not invoked unless all selected Apktool jobs finish successfully.
set -Eeuo pipefail
umask 077

query="${APKWORKBENCH_QUERY:-file manager}"
category="${APKWORKBENCH_CATEGORY:-TOOLS}"
discovery_limit="${APKWORKBENCH_DISCOVERY_LIMIT:-30}"
app_count="${APKWORKBENCH_APP_COUNT:-1}"

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

if ! command -v apkworkbench >/dev/null 2>&1; then
  echo "apkworkbench is not on PATH. Activate the APK Workbench virtual environment first." >&2
  exit 127
fi
if ! command -v python >/dev/null 2>&1; then
  echo "python is not on PATH. Activate the APK Workbench virtual environment first." >&2
  exit 127
fi
if [[ -z "$query" ]]; then
  echo "APKWORKBENCH_QUERY must not be empty." >&2
  exit 2
fi
if [[ ! "$category" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "APKWORKBENCH_CATEGORY must be a Google Play category identifier." >&2
  exit 2
fi
if ! positive_integer "$discovery_limit" || ! positive_integer "$app_count"; then
  echo "Discovery limit and app count must be positive integers." >&2
  exit 2
fi

# Fail before acquisition if a required executable is unavailable.
apkworkbench doctor

workspace="$(python -c 'from apkworkbench.core.config import Config; print(Config().get("workspace"))')"
mkdir -p "$workspace/logs" "$workspace/database/discovery_snapshots"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
pipeline_log="$workspace/logs/full_pipeline_${timestamp}_${BASHPID}.log"
exec > >(tee -a "$pipeline_log") 2>&1

catalog_path="$workspace/database/google_play_discovery.csv"
snapshot_dir="$workspace/database/discovery_snapshots"
if [[ -L "$catalog_path" ]]; then
  echo "Refusing symlinked discovery catalog: $catalog_path" >&2
  exit 1
fi
if [[ -f "$catalog_path" ]]; then
  previous_snapshot="$snapshot_dir/google_play_discovery_before_${timestamp}_${BASHPID}.csv"
  cp -p -- "$catalog_path" "$previous_snapshot"
  echo "Preserved previous discovery catalog: $previous_snapshot"
fi

echo "APK WORKBENCH — FULL GOOGLE PLAY PIPELINE"
echo "Started: $(date -u --iso-8601=seconds)"
echo "Workspace: $workspace"
echo "Discovery: category=$category query=$query limit=$discovery_limit"
echo "Acquisition target: $app_count app(s)"
echo "Order: DISCOVER -> DOWNLOAD -> VERIFY -> APKTOOL -> TRUFFLEHOG -> REPORT -> RECONCILE"
echo "Pipeline log: $pipeline_log"
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
new_snapshot="$snapshot_dir/google_play_discovery_after_${timestamp}_${BASHPID}.csv"
cp -p -- "$catalog_path" "$new_snapshot"
echo "Preserved this discovery catalog: $new_snapshot"

echo
echo "Starting verified acquisition and ordered processing..."
apkworkbench run --apk-count "$app_count"

echo
echo "FULL GOOGLE PLAY PIPELINE COMPLETE"
echo "Discovery snapshot: $new_snapshot"
echo "Pipeline log: $pipeline_log"
echo "Downloaded APKs/OBBs: $workspace/downloads"
echo "Apktool output: $workspace/results"
echo "Reports and verification evidence: $workspace/reports"
