# Inventory Report for APK-Workbench

## 1. Repo Structure

### Top-level files:
- activate-workbench.sh
- AGENTS.md
- CHANGELOG.md
- CONTRIBUTING.md
- .editorconfig
- force_surface.py
- .gitignore
- LICENSE
- plan.txt
- pyproject.toml
- README.md
- requirements.txt
- run_pipeline.py
- screenshot.jpg.odg
- SECURITY.md

### Key modules:
- src/apkworkbench/acquisition/ - Acquisition functionality
- src/apkworkbench/decompilation/ - Decompilation functionality  
- src/apkworkbench/database/ - Database components
- src/apkworkbench/analysis/ - Core analysis functionality including surface, DEX, and TruffleHog
- src/apkworkbench/sources/ - Data source implementations
- src/apkworkbench/cli/ - Command line interface functionality
- src/apkworkbench/reporting/ - Reporting functionality

### Test files:
- 27 test files in tests/ directory

## 2. Pipeline Stages

### Acquire
- Main files: src/apkworkbench/sources/google_play.py, src/apkworkbench/sources/google_play_anonymous.py, src/apkworkbench/acquisition/verification.py
- Entry function: ? (Not clearly identified)
- Output files: download manifests, verified APKs in downloads/ directory
- Status.json: Yes - required by pipeline smoothness

### Decompile  
- Main files: src/apkworkbench/decompilation/runner.py
- Entry function: ? (Not clearly identified)
- Output files: decoded APK components in apktool/ directory
- Status.json: Yes - required by pipeline smoothness

### Surface
- Main files: src/apkworkbench/analysis/apk_surface.py, src/apkworkbench/analysis/surface/sweep.py, src/apkworkbench/analysis/surface/classify.py, src/apkworkbench/analysis/surface/facts.py
- Entry function: ? (Not clearly identified)
- Output files: surface/facts.jsonl, surface/location_map.json, surface/static-analysis.json
- Status.json: Yes - required by pipeline smoothness

### DEX Analysis
- Main files: src/apkworkbench/analysis/androguard_dex.py
- Entry function: ? (Not clearly identified)
- Output files: DEX analysis artifacts, possibly shard files
- Status.json: Yes - required by pipeline smoothness

### Native Analysis  
- Main files: src/apkworkbench/analysis/surface/... (specific files not fully identified)
- Entry function: ? (Not clearly identified)
- Output files: Native analysis artifacts
- Status.json: Yes - required by pipeline smoothness

### TruffleHog
- Main files: src/apkworkbench/analysis/trufflehog.py, src/apkworkbench/analysis/trufflehog_adapter.py  
- Entry function: ? (Not clearly identified)
- Output files: trufflehog/verified.json, trufflehog/unverified.json, trufflehog/scan.json
- Status.json: Yes - required by pipeline smoothness

### Report
- Main files: src/apkworkbench/reporting/final_run.py, src/apkworkbench/reporting/generator.py (indirect)
- Entry function: ? (Not clearly identified)
- Output files: final-report.json, handoff.json, HTML reports
- Status.json: Yes - required by pipeline smoothness

### Reconcile
- Main files: src/apkworkbench/analysis/executor.py, src/apkworkbench/analysis/registry.py, src/apkworkbench/analysis/contracts.py
- Entry function: ? (Not clearly identified)
- Output files: Final validation, reconciliation artifacts
- Status.json: Yes - required by pipeline smoothness

## 3. Caps/Truncations/Filters Found

Due to the nature of the file access issues, I cannot definitively identify cap/filter patterns through the standard tools. I did not find any instances of MAX_, LIMIT_, TRUNCATE, [:100], break on count, verified-only, or Verified=true patterns in the source code examination, though this could potentially be due to issues with file content accessibility.

## 4. Crown Jewel Mapping Today

### DEX Strings:
- Evidence: As per documentation, should carry callers but this implementation cannot be confirmed from file content
- File:line evidence: Cannot be provided due to file content access limitations  

### Native JNI Mapping:
- Evidence: As per documentation, should map JNI entries but this implementation cannot be confirmed from file content
- File:line evidence: Cannot be provided due to file content access limitations

### Surface Findings Caller/Callee:
- Evidence: As per documentation, should carry caller/callee info but this implementation cannot be confirmed from file content
- File:line evidence: Cannot be provided due to file content access limitations

## 5. Tests

- 27 test files covering various pipeline components
- Tests asserting capped behavior: Cannot be definitively identified due to inability to read file contents
- Tests covering verification and other core functionality