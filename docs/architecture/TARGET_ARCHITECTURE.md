# Target Architecture

**Status:** Accepted for implementation in the engineering map; not yet implemented unless explicitly stated in the source tree.  
**Repository baseline:** main at commit 867f04e918197560018e38ef36d11bf67169f278 (2026-11-07).  
**Coordination source:** Airtable base appoG1faRDn2ztUOL, table Target Architecture Specification.

## Objective

Evolve APK WORKBENCH from a reliable acquisition/decompilation/TruffleHog pipeline into a modular Android APK surface-discovery and static-analysis workbench. Preserve working acquisition, integrity, reconciliation, decompilation, workspace safety and reporting behavior. Add a normalized analysis layer after verified artifact registration; do not rewrite the ingestion spine.

## Target pipeline

1. Source adapters.
2. Immutable acquisition manifest.
3. Artifact download and digest verification.
4. Artifact registry for APK, split APK and OBB components.
5. Parser and decompiler adapters.
6. Analyzer planning and registry.
7. Isolated analyzer executions.
8. Normalized findings and evidence locations.
9. Explainable correlation.
10. SQLite evidence store plus content-addressed objects.
11. Versioned JSON, CSV and HTML exports.

Each stage has explicit inputs, outputs, diagnostics, terminal states and resume behavior. Acquisition identity is distinct from analysis identity. A failed optional analyzer must not invalidate acquisition or erase successful results from other analyzers.

## Architecture areas

### 1. System boundary & pipeline

**Layer:** Architecture overview  
**Decision:** Accepted for implementation

**Design**

Preserve the proven acquisition/reconciliation/decompilation pipeline as the stable ingestion spine. Extend after verified artifact creation; do not rewrite Google Play acquisition as part of the analyzer pivot. Target flow: source adapters → immutable acquisition manifest → artifact download + digest verification → artifact registry → parser/decompiler adapters → analyzer plan → isolated analyzer executions → normalized findings/evidence → correlation → SQLite store → JSON/CSV/HTML exports. Every stage is independently resumable and has an explicit terminal state.

**Interfaces and contracts**

Each stage consumes immutable IDs and emits typed records; stage state is append-only for attempts with a current-state projection. Artifact identity is SHA-256 of exact bytes. Analysis identity is separate from acquisition identity. A failed optional analyzer must not invalidate acquisition or erase other analyzer results.

**Existing-code mapping**

Keep src/apkworkbench/sources, acquisition, decompilation, database/workspace.py and current CLI pipeline. Insert artifact registry and analysis orchestration after successful acquisition/decompilation. Existing manifests remain authoritative historical inputs.

**Constraints**

Do not change acquisition semantics while introducing analyzers. No automatic network behavior from static analyzers. Preserve workspace lock, path containment, atomic publication, hash re-checks, subprocess timeouts and reconciliation.

**Acceptance tests**

Integration test a real acquired APK through artifact registration, parsing, two independent analyzers, persistence and exports; kill/restart mid-run and prove idempotent resume. Reconcile every manifest component.

### 2. Analyzer contract & registry

**Layer:** Analysis framework  
**Decision:** Accepted for implementation

**Design**

Implement a deliberately small in-process registry of built-in analyzers first; do not build arbitrary third-party plugin loading. Each analyzer is a separately versioned unit with declared capabilities, accepted artifact kinds, config schema, resource limits and deterministic output. Registry creates an execution plan from requested analyzers and available artifact capabilities.

**Interfaces and contracts**

Analyzer protocol: definition() → AnalyzerDefinition(id, version, categories, input_kinds, required_capabilities, default_enabled, resource_profile); analyze(context) → AnalyzerResult(status, findings, diagnostics, metrics). AnalyzerContext is read-only and includes ArtifactView, parsed facts, run config and logger. Status values: success, partial, skipped, failed, timed_out, cancelled.

**Existing-code mapping**

New proposed modules analysis/registry.py, analysis/contracts.py, analysis/executor.py. Adapt src/apkworkbench/analysis/trufflehog.py as first legacy analyzer, preserving existing CLI compatibility during migration.

**Constraints**

Stable analyzer IDs and semantic versions. No dynamic imports from APK content. Each analyzer gets isolated output directory, timeout, output-byte ceiling and bounded concurrency. Analyzer failure is isolated; malformed output is rejected. Keep CLI independent of analyzer-specific implementation.

**Acceptance tests**

Contract tests with two fake analyzers; registry rejects duplicate IDs and unsupported inputs; one analyzer timeout/failure leaves another successful; deterministic rerun yields same normalized result.

### 3. Engineering coordination vs product runtime data

**Layer:** System boundary  
**Decision:** Accepted for implementation

**Design**

Airtable is the human/AI engineering coordination mirror for repository inventory, architecture, evidence-model design, decisions, defects, roadmap and release tracking. It is not part of the APK Workbench runtime and must not hold production APK contents, secrets, raw scan outputs or operational evidence as the application's database. The application uses its own local SQLite database plus content-addressed workspace files.

**Interfaces and contracts**

GitHub is source of truth for code and version history. SQLite/object store is source of truth for runtime analysis data. Airtable is source of truth only for collaborative engineering metadata. Cross-links use repository path + commit SHA, stable task/entity IDs and artifact hashes.

**Existing-code mapping**

Current Airtable base appoG1faRDn2ztUOL contains repository file inventory, component map, symbols, defects, decisions, roadmap and new target architecture/evidence specs. Runtime code currently uses CSV/JSON under workspace database/results/reports.

**Constraints**

Never couple CLI operation to Airtable availability or credentials. No APK uploads, secret values or end-user data in Airtable. Airtable sync is optional and out-of-band.

**Acceptance tests**

Run the CLI with no Airtable token/network and verify full acquisition/analysis/report pipeline works. Confirm runtime records and raw outputs are written locally and Airtable is not imported as a runtime dependency.

### 4. Artifact parsing & workspace

**Layer:** Parsing layer  
**Decision:** Accepted for implementation

**Design**

Introduce a normalized read-only ArtifactView over APK, split APK, DEX, AndroidManifest.xml, resources, native libraries, assets and OBB metadata. Parser adapters may use Androguard, JADX, Apktool or a minimal ZIP/XML parser; each parser advertises artifact types and capabilities. Parsing produces structured facts and source-coordinate indexes, not security verdicts. OBB remains a bundle component and is not treated as an APK.

**Interfaces and contracts**

ArtifactView exposes artifact_id, sha256, package/version metadata when available, container entries, manifest model, dex inventory, resource inventory, native library inventory and decoded-source roots. ParserResult carries parser name/version, status (success/partial/failed), diagnostics and generated artifact references.

**Existing-code mapping**

Extend src/apkworkbench/decompilation/runner.py and existing JADX/Apktool output layout. New modules proposed: analysis/artifacts.py, analysis/parsers/base.py, analysis/parsers/zip_apk.py, analysis/parsers/androguard.py. Existing output remains consumable.

**Constraints**

Treat APK contents as hostile input. ZIP traversal and zip bombs, oversized entries, malformed XML/DEX, decompression ratio, file count, total extracted bytes and parse time must be bounded. Parsers run without network and with least privilege. Never execute APK code.

**Acceptance tests**

Fixtures for base/split APK, malformed ZIP, manifest binary XML, DEX, native libs, OBB, zip-slip and decompression bombs. Verify exact source coordinates and partial status behavior.

### 5. Validation, supply chain & release

**Layer:** Quality gates  
**Decision:** Accepted for implementation

**Design**

Separate unit, contract, integration and operational tests. CI validates supported Python versions, lint, packaging, parser/analyzer fixtures and migration compatibility. A small legal test corpus is used for real external-tool integration. Release validation requires real APK end-to-end, dependency version capture, disk/CPU/memory observation, restart recovery and documented laptop installation.

**Interfaces and contracts**

Capture toolchain manifest (Python, OS, Java, JADX, Apktool, TruffleHog, MobSF/Androguard versions), package lock hashes, CI run URL, APK fixture SHA-256 and test outcome. External tool adapters expose doctor/health checks.

**Existing-code mapping**

Extend tests/, .github/workflows/, pyproject.toml, dependency detector and docs. Resolve README install branch mismatch and laptop return-code-3 as separate operational tasks.

**Constraints**

Pin supported tool versions; verify licenses and deployment model before adopting MobSF/Androguard. Do not claim runtime validation from mocked tests. Preserve PR chain until integration strategy is explicitly approved.

**Acceptance tests**

CI green + real APK integration + repeatable install + migration + resource/soak + clean workspace recovery. Release gate stays blocked until all required gates have evidence.

### 6. Reporting & user interface

**Layer:** Presentation layer  
**Decision:** Accepted for implementation

**Design**

Keep Click CLI as the first interface. Add commands to inspect artifact metadata, run selected analyzers, list findings, show evidence, export reports and explain coverage. Reports summarize app/artifact identity, analysis run, analyzers and versions, categories, confidence, verification state, evidence locations, diagnostics and limitations. Preserve current JSON/HTML reports through compatibility adapters.

**Interfaces and contracts**

Stable JSON schema version and CSV columns; HTML escapes all APK-derived strings and uses safe templates. Each report includes exact APK SHA-256, package/version when known, analyzer versions, rule-pack versions, config digest, timestamps and partial/failed analyzer notices.

**Existing-code mapping**

Extend src/apkworkbench/cli/main.py and src/apkworkbench/reporting/generator.py. Add reporting/serializers.py and versioned report schema docs.

**Constraints**

Do not imply a clean report means safe APK. Never expose unsanitized secrets. Treat all strings from APK as untrusted HTML. Report static-only scope and unsupported surfaces.

**Acceptance tests**

Golden report tests, XSS payload fixture, export round-trip, backward compatibility and partial-run reporting tests.

### 7. Execution isolation & resource governance

**Layer:** Runtime control plane  
**Decision:** Accepted for implementation

**Design**

Run analyzer jobs with deterministic scheduling and explicit resource profiles. Prefer subprocess isolation for heavyweight external tools (MobSF/JADX/Apktool/TruffleHog) and in-process execution only for bounded pure parsers. Capture stdout/stderr to per-execution files with truncation limits. Support cancellation, timeout, retry policy, and resumable execution without rerunning successful analyzers unless inputs/config/tool versions changed.

**Interfaces and contracts**

Execution record includes analyzer ID/version, artifact ID, analysis run ID, attempt number, started/finished timestamps, status, exit code, timeout, output references, stderr reference, resource metrics and config digest. Executor returns per-analyzer outcomes; aggregation computes run status.

**Existing-code mapping**

Extend current process helpers and decompilation runner patterns. Proposed analysis/executor.py and core/resource_limits.py. Reuse process-group termination and staged output patterns.

**Constraints**

Set configurable max APK bytes, extracted bytes, entry count, parser wall time, analyzer wall time, output bytes, concurrent jobs and workspace quota. Defaults conservative. External analyzer container network disabled, filesystem scoped read-only input + dedicated writable output.

**Acceptance tests**

Tests for timeout, cancellation, output flood, process tree termination, retry boundaries, concurrency cap, disk budget, path escape and crash recovery.

### 8. Evidence persistence & migration

**Layer:** Persistence  
**Decision:** Accepted for implementation

**Design**

Use SQLite as the normalized operational store, with schema version table and transactional migrations. Retain CSV/JSON as import/export interchange and human-readable artifacts, not the primary relational store. Store large raw outputs as content-addressed files with SHA-256 references; DB stores metadata and paths. Enable foreign keys, WAL where appropriate, busy timeout, explicit transactions and backup API.

**Interfaces and contracts**

Repository layer owns SQL; domain models must not issue SQL directly. Every write path validates IDs and foreign keys. Migration runner applies ordered migrations atomically and records version/checksum. Exports are generated from stable versioned DTOs, not direct table dumps.

**Existing-code mapping**

Current CSV implementation in src/apkworkbench/database/workspace.py remains the compatibility adapter during transition. Proposed database/sqlite.py, database/migrations/, database/repositories/, models/evidence.py.

**Constraints**

Never silently overwrite original manifests or historical CSV. Import must be idempotent and preserve source filename, row number, source hash and import timestamp. Back up before migration; rollback or restore on failure. Avoid storing raw secrets in DB/logs.

**Acceptance tests**

Migration tests against copied legacy workspace fixtures; idempotent double import; foreign-key checks; crash during migration; backup/restore; stable JSON/CSV golden exports.

### 9. Core static extractors

**Layer:** Analyzer suite  
**Decision:** Accepted for implementation

**Design**

Build focused deterministic extractors in increments: (1) manifest/components/permissions; (2) endpoints and network service indicators; (3) SDK/cloud/vendor fingerprints; (4) auth and embedded configuration; (5) WebView/JS bridge; (6) network security/TLS/trust configuration; (7) crypto/keystore; (8) dependency/library inventory; (9) secret detection. Keep each category independently runnable and report static evidence only.

**Interfaces and contracts**

Each rule emits finding_type, category, normalized value, confidence, rule_id, rationale, evidence locations and limitations. Rule packs are versioned data, not scattered regex constants. Preserve raw candidate and normalized candidate separately. Distinguish public identifiers/config from secrets; no credential validation or third-party login.

**Existing-code mapping**

Existing TruffleHog scanner remains as one analyzer. Proposed modules under analysis/extractors/ with manifest.py, endpoints.py, sdk_fingerprints.py, auth_config.py, webview.py, network_security.py, crypto.py, dependencies.py. Add curated versioned rule data under data/rules/.

**Constraints**

Static indicators are not runtime proof. No exploitation, credential use, auth bypass, dynamic testing or external calls. Vendor identification requires multiple corroborating signals where possible. Obfuscation and reflection limit coverage.

**Acceptance tests**

Golden fixture corpus per category, positive and negative examples, confidence calibration, rule provenance, false-positive tests, and regression tests across rule pack versions.


## Implementation order

1. Implement normalized evidence models and transactional SQLite migrations, retaining CSV/JSON compatibility.
2. Define the narrow analyzer contract and registry; adapt TruffleHog as the first legacy analyzer.
3. Implement execution orchestration, per-analyzer status, timeouts, cancellation, bounded output and resumability.
4. Build manifest/component and endpoint extractors first.
5. Add SDK/vendor/cloud, authentication/configuration, WebView, network-security, crypto and dependency inventory extractors in focused increments.
6. Add explainable finding correlation and reporting compatibility.
7. Validate with real APKs and actual external binaries; retain CI, resource, restart and installation gates.

## Explicit non-goals for the first implementation

- No arbitrary third-party plugin loading framework.
- No APK code execution or dynamic analysis by default.
- No network calls from static analyzers.
- No live credential validation, third-party authentication, exploitation or account interaction.
- No Airtable runtime dependency.
- No immediate adoption of MobSF and Androguard without a same-corpus comparison.

## System-of-record boundaries

- **GitHub:** source code, branches, commits, pull requests and version history.
- **Local SQLite plus content-addressed workspace objects:** operational APK, artifact, analysis and evidence data.
- **Airtable:** collaborative engineering inventory, architecture, decisions, defects, roadmap and release tracking only.

Airtable availability must never be required to run the CLI. Do not upload APKs, raw findings, credentials or sensitive runtime evidence to Airtable.

## Definition of implementation-ready

The specification is considered sufficient to start coding. Resolve details through code, tests and measured integration—not another open-ended planning phase. Any material architecture change should be recorded as a dated decision with the reason and affected commit/PR.
