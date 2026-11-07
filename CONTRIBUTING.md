# Contributing

Thanks for taking an interest in APK WORKBENCH.

## Project scope

APK WORKBENCH is a Python-only, Linux-native CLI. Keep the runtime implementation in Python. Do not introduce a JavaScript/TypeScript backend, web service, database server, or cloud dependency unless the project owner explicitly changes the architecture.

The core execution model is deliberately sequential and auditable:

- one artifact at a time;
- one external process at a time;
- explicit integrity checks at trust boundaries;
- persistent, reviewable state;
- fail-closed behavior when a security guarantee cannot be established.

## Development setup

Use Python 3.10 or newer:

```bash
git clone https://github.com/xdial9/apk-workbench.git
cd apk-workbench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Before submitting a change

Run the full test suite and linter:

```bash
python -m pytest
ruff check .
```

Add or update tests for behavior changes. Tests must not require live F-Droid access, real APK downloads, or external decompiler/scanner installations; mock network and subprocess boundaries and use temporary workspaces.

## Security-sensitive changes

Changes to signature verification, fingerprint pinning, artifact hashing, download publication, filesystem paths, subprocess invocation, secret redaction, and report generation require explicit regression tests.

Never weaken a verification check simply to make a failing test or live operation pass. Document the threat-model impact and the evidence supporting any trust configuration change.

Do not add real APKs, API keys, credentials, scan outputs, user data, or runtime workspace files to Git.

## Pull requests

Keep changes focused. Describe:

1. the behavior being changed;
2. why the change is needed;
3. security and data-integrity implications;
4. tests run and their results;
5. any known limitations or manual verification still required.

Do not claim a live integration test when only mocks or unit tests were run.
