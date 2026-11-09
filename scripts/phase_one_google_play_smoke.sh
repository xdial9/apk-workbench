#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
PACKAGE_ID="${1:-${APKWORKBENCH_PHASE_ONE_PACKAGE:-com.roleplai.app}}"
SEARCH_QUERY="${APKWORKBENCH_PHASE_ONE_QUERY:-RolePlai}"
VENV_DIR="${APKWORKBENCH_VENV:-${REPO_ROOT}/.venv}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEFAULT_WORKSPACE="${HOME}/APK-Workbench-PhaseOne/${PACKAGE_ID}-${TIMESTAMP}"
WORKSPACE="${APKWORKBENCH_WORKSPACE:-${DEFAULT_WORKSPACE}}"

if [[ ! "${PACKAGE_ID}" =~ ^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$ ]]; then
  echo "Invalid Android package ID: ${PACKAGE_ID}" >&2
  exit 2
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  python3 -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip
python -m pip install -e "${REPO_ROOT}"

python - <<'PY'
import sys

try:
    from playstore_cli import store
    account = store.load_account()
    device = store.load_device()
except Exception as exc:
    print(
        "Saved Google Play account/device session is unavailable. "
        "Configure it with playstore-cli login and playstore-cli checkin first.",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc

if not account or not device:
    print(
        "Saved Google Play account/device session is incomplete. "
        "Configure it with playstore-cli login and playstore-cli checkin first.",
        file=sys.stderr,
    )
    raise SystemExit(2)

print("Saved Google Play account/device session found; credentials were not displayed.")
PY

mkdir -p -- "${WORKSPACE}"
WORKSPACE="$(cd -- "${WORKSPACE}" && pwd -P)"
if [[ -n "$(find "${WORKSPACE}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Phase One workspace is not empty: ${WORKSPACE}" >&2
  echo "Choose a fresh path with APKWORKBENCH_WORKSPACE to avoid overwriting prior evidence." >&2
  exit 2
fi
export APKWORKBENCH_WORKSPACE="${WORKSPACE}"

PACKAGE_FILE="$(mktemp)"
trap 'rm -f "${PACKAGE_FILE}"' EXIT
printf '%s\n' "${PACKAGE_ID}" > "${PACKAGE_FILE}"

echo "[Phase 1/3] Enumerating Google Play search results for: ${SEARCH_QUERY}"
apkworkbench discover \
  --query "${SEARCH_QUERY}" \
  --limit 50 \
  --per-query 25 \
  --packages-file "${PACKAGE_FILE}" \
  2>&1 | tee "${WORKSPACE}/phase-one-discovery.log"

python - "${WORKSPACE}/database/google_play_discovery.csv" "${PACKAGE_ID}" <<'PY'
import csv
import sys
from pathlib import Path

catalogue = Path(sys.argv[1])
package_id = sys.argv[2]
if not catalogue.is_file() or catalogue.stat().st_size == 0:
    raise SystemExit("Google Play discovery did not create a catalogue")
with catalogue.open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle))
if not rows:
    raise SystemExit("Google Play discovery returned no candidates")
if not any(row.get("package_id") == package_id for row in rows):
    raise SystemExit(f"Target package was not added to the discovery catalogue: {package_id}")
print(f"Discovery recorded {len(rows)} candidates and includes {package_id}.")
PY

echo "[Phase 2/3] Downloading the selected package and all Play bundle components"
apkworkbench download --package "${PACKAGE_ID}" \
  2>&1 | tee "${WORKSPACE}/phase-one-download.log"

echo "[Phase 3/3] Verifying files on disk, Play digests, and frozen run manifest"
python "${REPO_ROOT}/scripts/validate_phase_one_run.py" "${WORKSPACE}" --package-id "${PACKAGE_ID}"

echo
echo "PHASE ONE VERIFIED"
echo "APK Workbench workspace: ${WORKSPACE}"
echo "Downloaded bundle:      ${WORKSPACE}/downloads"
echo "Run manifests:          ${WORKSPACE}/database/run_manifests"
echo "Validation report:      ${WORKSPACE}/phase-one-result.json"
echo "No JADX, Apktool, TruffleHog, or downstream analysis was run."
