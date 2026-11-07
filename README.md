# APK Workbench

Linux-native Python tooling for the sequential discovery, acquisition, decompilation, static inspection, and cataloguing of Android APK files.

The project emphasizes reproducibility, integrity checks, persistent records, and transparent execution. It orchestrates specialist tools rather than reimplementing them.

## Pipeline

1. **Discover** APK artifacts from configured sources (initially F-Droid).
2. **Freeze** a run manifest so the selected inputs are auditable.
3. **Download** artifacts sequentially and verify their advertised SHA-256.
4. **Decompile** each APK with JADX and Apktool, one process at a time.
5. **Scan** decompiled files locally with TruffleHog; do not actively verify discovered credentials.
6. **Report** metadata and findings in machine-readable and human-readable formats.

A failed integrity check must never be treated as a successful acquisition. Findings are evidence for manual review, not proof of exploitability.

## Project status

The repository is being bootstrapped. It is not yet a production-ready release. Interfaces and command behavior will be added incrementally, with tests accompanying each component.

## Requirements

- Linux (Debian/Ubuntu are primary targets)
- Python 3.10+
- Java runtime compatible with the installed JADX release
- JADX
- Apktool
- GPG
- TruffleHog

Install the Python package in editable mode:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Then run:

```bash
apkworkbench doctor
```

The CLI is under active development; commands will become available as implementation tasks land.

## Design constraints

- Strict sequential execution; no concurrent APK processing.
- SHA-256 verification before an APK enters permanent acquisition history.
- Frozen run manifests and immutable download history.
- Atomic updates for mutable state.
- Preserve complete JADX and Apktool outputs.
- Redact secret material in reports. Never print raw credential values.
- Do not dynamically execute downloaded APKs or automatically exploit findings.

## Repository layout

```text
src/apkworkbench/     Python application
tests/                Automated tests
docs/                 Design and implementation notes
```

The runtime workspace is separate from the source checkout and is configurable by the user.

## Development

```bash
python -m pytest
ruff check .
```

## Disclaimer

APK Workbench is intended for authorized research, defensive security review, interoperability analysis, and software inventory. Only acquire and analyze applications where you have the legal right and authorization to do so. The maintainers provide the software without warranties; users are responsible for complying with applicable laws, licenses, and service terms.
