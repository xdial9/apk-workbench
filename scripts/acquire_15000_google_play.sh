#!/usr/bin/env bash
set -Eeuo pipefail

batch_size="${APKWORKBENCH_BATCH_SIZE:-100}"
batch_count="${APKWORKBENCH_BATCHES:-150}"
pause_seconds="${APKWORKBENCH_BATCH_PAUSE_SECONDS:-5}"

if [[ ! "$batch_size" =~ ^[1-9][0-9]*$ ]]; then
  echo "APKWORKBENCH_BATCH_SIZE must be a positive integer." >&2
  exit 2
fi
if [[ ! "$batch_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "APKWORKBENCH_BATCHES must be a positive integer." >&2
  exit 2
fi

target=$((batch_size * batch_count))
echo "Google Play Store acquisition target: up to $target apps"
echo "Batch size: $batch_size | batches: $batch_count | pause: ${pause_seconds}s"
echo "The script stops on the first incomplete/failed batch. Re-run it to resume; completed package IDs are skipped."

for ((batch = 1; batch <= batch_count; batch++)); do
  echo
  echo "========== GOOGLE PLAY BATCH $batch/$batch_count =========="
  if apkworkbench run --apk-count "$batch_size"; then
    echo "Batch $batch completed."
  else
    status=$?
    echo "Batch $batch stopped with exit code $status." >&2
    echo "Successful Google Play acquisitions remain recorded. Resolve the reported issue and rerun this script to continue." >&2
    exit "$status"
  fi

  if ((batch < batch_count)) && [[ "$pause_seconds" != "0" ]]; then
    sleep "$pause_seconds"
  fi
done

echo
echo "Requested batch count completed. Run 'apkworkbench status' and inspect run reconciliations."
