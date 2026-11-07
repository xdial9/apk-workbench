![APK WORKBENCH](docs/assets/apk-workbench-banner.svg)

# Contributing to APK WORKBENCH

**Python-only · Linux-native · Sequential · Verifiable**

Changes should strengthen reliability, clarity, reproducibility, or the integrity of the processing record.

## Project boundaries

APK WORKBENCH is a Python CLI. Keep runtime implementation in Python. Do not introduce a JavaScript/TypeScript backend, web service, database server, or cloud dependency unless the project owner explicitly changes the architecture.

The execution model is deliberately simple and auditable:

- One APK at a time.
- One external subprocess at a time.
- Verify data at trust boundaries.
- Preserve immutable acquisition records.
- Fail closed when a security guarantee cannot be established.

## Development setup

~~~bash
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

Python 3.10 or newer is required.

## Required checks

~~~bash
python -m pytest
ruff check .
~~~

Tests should use temporary workspaces and mocked HTTP/subprocess boundaries. They must not depend on live F-Droid access, external APK downloads, or local installations of JADX, Apktool, or TruffleHog.

## Regression-test expectations

Add or update tests for changed behavior. Security-sensitive changes require explicit regression coverage, especially changes to:

- OpenPGP fingerprint pinning and detached-signature verification.
- URL validation, download bounds, and artifact SHA-256 checks.
- Atomic file publication and immutable run manifests.
- Manifest-scoped processing and cross-run isolation.
- Filesystem path validation and symlink handling.
- Subprocess timeouts and sequential execution.
- TruffleHog credential verification, verified-only results, output limits, and secret sanitization.
- Report generation.

A run-scoped operation must use its immutable manifest. It must not silently broaden a batch by falling back to unrelated workspace records.

## Data hygiene

Never commit:

- Downloaded APKs or decompiler output.
- Runtime workspace databases or manifests.
- Scanner outputs or raw findings.
- Credentials, access tokens, API keys, or personal data.
- Local virtual environments or tool binaries.

Use synthetic fixtures in tests.

## Pull-request description

Keep changes focused and include:

1. What behavior changed.
2. Why the change was needed.
3. Security and data-integrity implications.
4. Tests and lint checks performed.
5. Remaining limitations or manual validation still required.

Do not describe mocked tests as live integration tests. If real tool execution was not performed, state that explicitly.
