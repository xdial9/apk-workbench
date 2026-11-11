#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DEBIAN_FRONTEND=noninteractive

echo "==> Installing APK Workbench system tools (Debian 13)"
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  apktool \
  ca-certificates \
  curl \
  default-jre-headless \
  git \
  jq \
  lazygit \
  unzip

echo "==> Installing pinned TruffleHog release"
TRUFFLEHOG_VERSION="v3.99.8"
if ! command -v trufflehog >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sudo sh -s -- -b /usr/local/bin "$TRUFFLEHOG_VERSION"
fi

echo "==> Creating the project virtual environment"
if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
  python -m venv "$ROOT_DIR/.venv"
fi

echo "==> Installing APK Workbench and its declared development dependencies"
"$ROOT_DIR/.venv/bin/python" -m pip install -e ".[dev]"

echo
echo "==> Environment summary"
python --version
"$ROOT_DIR/.venv/bin/python" -m pip show androguard | sed -n '1,2p'
java -version 2>&1 | head -n 1
apktool --version
lazygit --version
trufflehog --version

echo
echo "Setup complete. Start the Git TUI with: lazygit"
echo "Run tests with: .venv/bin/python -m pytest -q"
