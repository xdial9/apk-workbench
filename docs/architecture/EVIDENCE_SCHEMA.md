# Evidence Data Model

**Status:** Target schema accepted for implementation; this is a logical model, not a claim that SQLite tables already exist.  
**Coordination source:** Airtable base appoG1faRDn2ztUOL, table Evidence Schema Specification.

## Core principles

1. Exact APK bytes are immutable and identified by SHA-256.
2. App identity, artifact version, delivery component, acquisition event and analysis run are separate concepts.
3. Every finding records the analyzer and version that emitted it.
4. Every finding may have multiple precise evidence locations.
5. Static indicators are not equivalent to verified behavior or exploitability.
6. Acquisition attempts and analyzer executions are append-only; retries do not overwrite history.
7. SQLite is the normalized operational store; CSV/JSON remain import/export formats.
8. Large outputs live in a content-addressed object store; the database stores metadata and references.

## Entity definitions

### 1. App Identity

**Priority:** MVP

**Purpose:** Stable logical Android app identity independent of any particular APK build.

**Fields and types**

package_id TEXT NOT NULL; canonical_app_id TEXT optional; application_label TEXT; developer_name TEXT; first_seen_at DATETIME; last_seen_at DATETIME; acquisition_sources JSON.

**Keys and constraints**

PK app_id UUID; UNIQUE(package_id) where source namespace permits; package ID is descriptive identity, not cryptographic identity.

**Relationships**

1:N Artifact Version; 1:N Acquisition Observation.

**Lifecycle and provenance**

Created from discovery/acquisition metadata; merge observations only with explicit package-ID/source policy.

**Migration and compatibility**

Import discovery CSV rows into observations; preserve original row and source. Do not collapse package variants without evidence.

### 2. Finding Relationship & Correlation

**Priority:** MVP+1

**Purpose:** Explainable links between findings without deleting distinct evidence.

**Fields and types**

relationship_id UUID; source_finding_id UUID; target_finding_id UUID; relation_type ENUM(duplicate_value, same_endpoint, same_vendor, version_change, corroborates, conflicts, derived_from); confidence REAL; rationale TEXT; correlation_rule_id TEXT; created_at DATETIME.

**Keys and constraints**

PK relationship_id; no self-links; unique source+target+relation+rule; confidence 0..1; relationships reversible and retain both findings.

**Relationships**

N:N Finding to Finding.

**Lifecycle and provenance**

Created after normalization; correlation rule/version recorded; recomputable from immutable findings.

**Migration and compatibility**

No existing equivalent; additive model. Do not collapse duplicate findings in initial migration.

### 3. Bundle Component

**Priority:** MVP

**Purpose:** A downloaded or expected component of a delivery bundle, including base/split APK and OBB.

**Fields and types**

component_id UUID; artifact_id UUID nullable until verified; bundle_id UUID; filename TEXT; kind ENUM(base_apk, split_apk, obb, asset_pack, other); size_bytes INTEGER; expected_hash_algorithm TEXT; expected_hash TEXT; actual_sha256 TEXT; verification_status ENUM; local_object_ref TEXT.

**Keys and constraints**

PK component_id; unique(bundle_id, filename); expected digest algorithm/value retained exactly. Never label Play SHA-1 as SHA-256. Artifact link required for APK after verification; OBB may remain non-APK component.

**Relationships**

N:1 Artifact Version when APK; N:1 Acquisition Bundle.

**Lifecycle and provenance**

Created from delivery metadata; finalized after download and verification; preserve failed/partial components.

**Migration and compatibility**

Translate manifest and bundle JSON into component rows; preserve legacy hash algorithm and status verbatim.

### 4. Finding

**Priority:** MVP

**Purpose:** A normalized interpretation emitted by an analyzer; not proof of runtime use or exploitability.

**Fields and types**

finding_id UUID; execution_id UUID; artifact_id UUID; category TEXT; finding_type TEXT; title TEXT; normalized_value TEXT nullable; value_fingerprint TEXT nullable; severity TEXT nullable; confidence REAL 0..1; verification_state ENUM(static_unverified, corroborated_static, manually_verified, runtime_verified, rejected); rationale TEXT; rule_id TEXT; rule_version TEXT; first_seen_at; last_seen_at; dedup_key TEXT.

**Keys and constraints**

PK finding_id; FK execution/artifact; confidence range 0..1; do not force severity where category lacks defensible severity; dedup key never replaces evidence; secret values redacted or fingerprinted.

**Relationships**

N:1 execution; N:1 artifact; 1:N Evidence Location; N:N via Finding Relationship.

**Lifecycle and provenance**

Immutable per run; state changes captured as analyst assessment events or status history; static and runtime verification separate.

**Migration and compatibility**

TruffleHog findings map to secret category while preserving detector metadata and sanitized fields. Legacy line/path becomes Evidence Location.

### 5. Evidence Location

**Priority:** MVP

**Purpose:** Precise, reproducible location supporting one finding; multiple locations per finding are first-class.

**Fields and types**

evidence_id UUID; finding_id UUID; artifact_id UUID; container_path TEXT; source_path TEXT; line_start/end INTEGER; byte_offset_start/end INTEGER; dex_class TEXT; method_signature TEXT; resource_name TEXT; manifest_xpath TEXT; evidence_kind TEXT; snippet_redacted TEXT; snippet_sha256 TEXT; extractor_coordinate JSON.

**Keys and constraints**

PK evidence_id; FK finding/artifact; coordinate fields nullable by format; path normalized relative to artifact/workspace; never store absolute host path as canonical coordinate.

**Relationships**

N:1 finding; N:1 artifact; optionally linked parser object.

**Lifecycle and provenance**

Generated by analyzer/parser; retain exact coordinate scheme and parser version; snippets sanitized and size-bounded.

**Migration and compatibility**

Legacy file_path+line maps directly; mark unknown coordinate fields null rather than fabricate them.

### 6. Acquisition Observation & Run

**Priority:** MVP

**Purpose:** Append-only source and acquisition provenance; distinguish repeated downloads from artifact identity.

**Fields and types**

acquisition_run_id UUID; source_adapter_id TEXT; started_at/finished_at; status; query/config digest; manifest_ref; run_id; observation_id; app_id; component_id; requested_at; downloaded_at; source_uri redacted; expected/actual digest; attempt_no; error_code; error_summary.

**Keys and constraints**

PK run/observation IDs; append-only attempts; no overwrite of frozen manifest; credentials/tokens never stored. Unique idempotency key per run+component+attempt.

**Relationships**

Run 1:N observations; observation N:1 app/component; component resolves to artifact.

**Lifecycle and provenance**

Record every attempt; final run status derived from frozen manifest reconciliation, not merely last command exit.

**Migration and compatibility**

Import discovery/download_attempts/run_manifests/download_history; retain source table, row number, source hash and import ID.

### 7. Parser Result, Raw Output & Schema Migration

**Priority:** MVP

**Purpose:** Preserve parser outputs, provenance, schema evolution and external files safely.

**Fields and types**

parser_result_id UUID; analysis_run_id; artifact_id; parser_id/version; status; capabilities JSON; output_ref; output_sha256; diagnostics JSON. raw_output_id UUID; content_sha256; media_type; byte_size; relative_object_path; retention_class. schema_migration(version, checksum, applied_at).

**Keys and constraints**

PK IDs; content-addressed objects immutable; verify digest on read; migration version/checksum monotonic; FK enforcement; no dangling evidence references.

**Relationships**

Run 1:N parser results; parser result N:1 artifact; output refs referenced by executions/findings.

**Lifecycle and provenance**

Large raw data stored outside DB under content-addressed workspace object store; SQLite stores metadata. Apply migrations transactionally with backup.

**Migration and compatibility**

Legacy JSON/HTML/CSV remain export/import artifacts; do not bulk-inline blobs into SQLite. Import records keep source file/row/hash.

### 8. Analyzer Definition & Execution

**Priority:** MVP

**Purpose:** Analyzer identity/version and each concrete attempt to execute it.

**Fields and types**

definition: analyzer_id TEXT; version TEXT; categories[]; input_kinds[]; required_capabilities[]; config_schema_version; resource_profile. execution: execution_id UUID; analysis_run_id; analyzer_id/version; attempt_no; started/finished; status; exit_code; timeout_ms; output_bytes; stdout_ref; stderr_ref; diagnostics JSON; metrics JSON; config_digest.

**Keys and constraints**

PK analyzer_id+version; PK execution_id; UNIQUE(analysis_run_id, analyzer_id, attempt_no); statuses success/partial/skipped/failed/timed_out/cancelled; output refs content-addressed.

**Relationships**

Definition 1:N executions; run 1:N executions; execution 1:N findings.

**Lifecycle and provenance**

Record exact tool/analyzer version and effective config; retries create new execution rows; failure does not delete prior output.

**Migration and compatibility**

TruffleHog maps to analyzer ID trufflehog with verification disabled; preserve legacy scan JSON as raw output reference.

### 9. Analysis Run

**Priority:** MVP

**Purpose:** A reproducible analysis request over one or more exact artifacts, separate from acquisition.

**Fields and types**

analysis_run_id UUID; artifact_id UUID; started_at; finished_at; status; requested_analyzers JSON; effective_config_digest; parser/toolchain_snapshot JSON; rule_pack_snapshot JSON; host/runtime metadata JSON; initiated_by TEXT.

**Keys and constraints**

PK analysis_run_id; immutable input artifact hash; unique run ID; terminal status derived from all executions; reruns create new run or explicit attempt, never overwrite history.

**Relationships**

N:1 Artifact Version; 1:N Analyzer Execution; 1:N Finding (via execution).

**Lifecycle and provenance**

Created when analysis starts; snapshots all material configuration and versions. Resume only when input/config/analyzer identity matches.

**Migration and compatibility**

Legacy processing_status maps to a status projection only; historical CSV rows become imported run observations where provenance supports it.

### 10. Artifact Version

**Priority:** MVP

**Purpose:** Exact immutable APK bytes and associated release metadata.

**Fields and types**

artifact_id UUID; app_id UUID; package_id TEXT; version_code INTEGER; version_name TEXT; apk_sha256 CHAR(64); signer_cert_sha256[]; min_sdk INTEGER; target_sdk INTEGER; acquired_at DATETIME; source_id TEXT; metadata_json JSON.

**Keys and constraints**

PK artifact_id; UNIQUE(apk_sha256); CHECK SHA-256 hex length 64; never update hash after creation. Same APK bytes may be observed under multiple package/version labels; preserve observations separately.

**Relationships**

N:1 App Identity; 1:N Bundle Component; 1:N Analysis Run; 1:N Acquisition Observation.

**Lifecycle and provenance**

Artifact registered only after full-file SHA-256 verification; parser-derived metadata is marked with provenance.

**Migration and compatibility**

Import download_history and run manifests; resolve duplicates by exact SHA-256 only. Do not deduplicate on package/version.


## Relationship overview

App Identity 1-to-many Artifact Version  
Artifact Version 1-to-many Bundle Component  
Acquisition Run 1-to-many Acquisition Observation  
Artifact Version 1-to-many Analysis Run  
Analysis Run 1-to-many Analyzer Execution  
Analyzer Definition 1-to-many Analyzer Execution  
Analyzer Execution 1-to-many Finding  
Finding 1-to-many Evidence Location  
Finding many-to-many Finding through typed, explainable relationships  
Analysis Run 1-to-many Parser Result and Raw Output references

## SQLite implementation constraints

- Enable foreign keys on every connection; use explicit transactions and ordered, checksummed schema migrations.
- Use WAL and a bounded busy timeout where appropriate; provide backup/restore behavior.
- Keep SQL in repository/data-access modules, not domain objects.
- Store timestamps in a consistent UTC representation.
- Use UUIDs or stable opaque identifiers for records; never use mutable display labels as primary keys.
- Store artifact bytes and large raw outputs outside SQLite under content-addressed paths; verify object hashes when reading.
- Sanitize secrets before persistence and logs. Keep raw source snippets bounded and redacted.
- Preserve original CSV/JSON files and provenance during import; never silently replace historical ledgers.
- Make legacy imports idempotent and retain source filename, row number, source digest and import timestamp.

## Confidence and verification semantics

- static_unverified: extracted from static artifact evidence; no independent confirmation.
- corroborated_static: supported by multiple independent static signals.
- manually_verified: reviewed and confirmed by a human using a documented method.
- runtime_verified: confirmed through an explicitly authorized runtime test; not implied by static scanning.
- rejected: assessed as false positive or otherwise invalid, with rationale retained.

Do not force a severity score onto categories where severity cannot be defended. Confidence, severity and verification state are separate dimensions.

## Migration boundary

The current CSV acquisition ledgers and TruffleHog JSON remain readable during migration. Build an idempotent importer and parity tests before switching writes. Preserve immutable manifests and historical files. New normalized exports must be versioned and generated from stable DTOs, not raw SQL table dumps.
