#!/usr/bin/env bash
# Activate the APK Workbench virtual environment and its unified local workspace.
# Use with: source ./activate-workbench.sh

_WORKBENCH_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$_WORKBENCH_ROOT/.venv/bin/activate"

export APKWORKBENCH_WORKSPACE="$_WORKBENCH_ROOT/workspace"
export APKWORKBENCH_CONFIG_DIR="$_WORKBENCH_ROOT/config"
export APKWORKBENCH_STATE_DIR="$_WORKBENCH_ROOT/state"

cd "$_WORKBENCH_ROOT"
unset _WORKBENCH_ROOT

printf 'APK Workbench active: %s\n' "$PWD"
printf 'Workspace: %s\n' "$APKWORKBENCH_WORKSPACE"
