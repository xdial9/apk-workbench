"""Normalized, versioned SQLite store for APK analysis evidence.

The legacy WorkspaceDatabase CSV ledgers remain the acquisition compatibility layer.
This database stores normalized artifact, analysis, finding and evidence records.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EvidenceDatabaseError(RuntimeError):
    """Raised when evidence storage or validation fails."""


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_EXECUTION_STATUSES = {
    "success", "partial", "skipped", "failed", "timed_out", "cancelled"
}
ALLOWED_VERIFICATION_STATES = {
    "static_unverified", "corroborated_static", "manually_verified",
    "runtime_verified", "rejected"
}
ALLOWED_RELATION_TYPES = {
    "duplicate_value", "same_endpoint", "same_vendor", "version_change",
    "corroborates", "conflicts", "derived_from"
}

MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        """
        CREATE TABLE app_identity (
            app_id TEXT PRIMARY KEY,
            package_id TEXT NOT NULL UNIQUE,
            canonical_app_id TEXT,
            application_label TEXT,
            developer_name TEXT,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            acquisition_sources_json TEXT NOT NULL DEFAULT '[]'
        )
        """,
        """
        CREATE TABLE artifact_version (
            artifact_id TEXT PRIMARY KEY,
            app_id TEXT NOT NULL REFERENCES app_identity(app_id) ON DELETE RESTRICT,
            package_id TEXT NOT NULL,
            version_code INTEGER,
            version_name TEXT,
            apk_sha256 TEXT NOT NULL UNIQUE
                CHECK(length(apk_sha256) = 64 AND apk_sha256 NOT GLOB '*[^0-9a-f]*'),
            signer_cert_sha256_json TEXT NOT NULL DEFAULT '[]',
            min_sdk INTEGER,
            target_sdk INTEGER,
            acquired_at TEXT,
            source_id TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE acquisition_run (
            acquisition_run_id TEXT PRIMARY KEY,
            source_adapter_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            config_digest TEXT,
            manifest_ref TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )
        """,
        """
        CREATE TABLE bundle_component (
            component_id TEXT PRIMARY KEY,
            acquisition_run_id TEXT NOT NULL
                REFERENCES acquisition_run(acquisition_run_id) ON DELETE RESTRICT,
            bundle_id TEXT NOT NULL,
            artifact_id TEXT REFERENCES artifact_version(artifact_id) ON DELETE RESTRICT,
            filename TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('base_apk','split_apk','obb','asset_pack','other')),
            size_bytes INTEGER CHECK(size_bytes IS NULL OR size_bytes >= 0),
            expected_hash_algorithm TEXT,
            expected_hash TEXT,
            actual_sha256 TEXT,
            verification_status TEXT NOT NULL DEFAULT 'pending',
            local_object_ref TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(acquisition_run_id, bundle_id, filename)
        )
        """,
        """
        CREATE TABLE acquisition_observation (
            observation_id TEXT PRIMARY KEY,
            acquisition_run_id TEXT NOT NULL
                REFERENCES acquisition_run(acquisition_run_id) ON DELETE RESTRICT,
            app_id TEXT REFERENCES app_identity(app_id) ON DELETE RESTRICT,
            component_id TEXT REFERENCES bundle_component(component_id) ON DELETE RESTRICT,
            source_uri_redacted TEXT,
            expected_digest_algorithm TEXT,
            expected_digest TEXT,
            actual_sha256 TEXT,
            requested_at TEXT,
            downloaded_at TEXT,
            attempt_no INTEGER NOT NULL DEFAULT 1 CHECK(attempt_no > 0),
            outcome TEXT NOT NULL,
            error_code TEXT,
            error_summary TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )
        """,
        """
        CREATE TABLE analysis_run (
            analysis_run_id TEXT PRIMARY KEY,
            artifact_id TEXT NOT NULL
                REFERENCES artifact_version(artifact_id) ON DELETE RESTRICT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            requested_analyzers_json TEXT NOT NULL DEFAULT '[]',
            effective_config_digest TEXT,
            toolchain_snapshot_json TEXT NOT NULL DEFAULT '{}',
            rule_pack_snapshot_json TEXT NOT NULL DEFAULT '{}',
            runtime_metadata_json TEXT NOT NULL DEFAULT '{}'
        )
        """,
        """
        CREATE TABLE analyzer_definition (
            analyzer_id TEXT NOT NULL,
            version TEXT NOT NULL,
            categories_json TEXT NOT NULL DEFAULT '[]',
            input_kinds_json TEXT NOT NULL DEFAULT '[]',
            required_capabilities_json TEXT NOT NULL DEFAULT '[]',
            config_schema_version TEXT,
            resource_profile_json TEXT NOT NULL DEFAULT '{}',
            default_enabled INTEGER NOT NULL DEFAULT 0 CHECK(default_enabled IN (0,1)),
            PRIMARY KEY(analyzer_id, version)
        )
        """,
        """
        CREATE TABLE analyzer_execution (
            execution_id TEXT PRIMARY KEY,
            analysis_run_id TEXT NOT NULL
                REFERENCES analysis_run(analysis_run_id) ON DELETE RESTRICT,
            analyzer_id TEXT NOT NULL,
            analyzer_version TEXT NOT NULL,
            attempt_no INTEGER NOT NULL DEFAULT 1 CHECK(attempt_no > 0),
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL CHECK(status IN
                ('success','partial','skipped','failed','timed_out','cancelled')),
            exit_code INTEGER,
            timeout_ms INTEGER CHECK(timeout_ms IS NULL OR timeout_ms >= 0),
            output_bytes INTEGER CHECK(output_bytes IS NULL OR output_bytes >= 0),
            stdout_ref TEXT,
            stderr_ref TEXT,
            diagnostics_json TEXT NOT NULL DEFAULT '[]',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            config_digest TEXT,
            FOREIGN KEY(analyzer_id, analyzer_version)
                REFERENCES analyzer_definition(analyzer_id, version) ON DELETE RESTRICT,
            UNIQUE(analysis_run_id, analyzer_id, analyzer_version, attempt_no)
        )
        """,
        """
        CREATE TABLE finding (
            finding_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL
                REFERENCES analyzer_execution(execution_id) ON DELETE RESTRICT,
            artifact_id TEXT NOT NULL
                REFERENCES artifact_version(artifact_id) ON DELETE RESTRICT,
            category TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            title TEXT NOT NULL,
            normalized_value TEXT,
            value_fingerprint TEXT,
            severity TEXT,
            confidence REAL CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
            verification_state TEXT NOT NULL DEFAULT 'static_unverified'
                CHECK(verification_state IN
                    ('static_unverified','corroborated_static','manually_verified',
                     'runtime_verified','rejected')),
            rationale TEXT,
            rule_id TEXT,
            rule_version TEXT,
            first_seen_at TEXT,
            last_seen_at TEXT,
            dedup_key TEXT,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE evidence_location (
            evidence_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL
                REFERENCES finding(finding_id) ON DELETE CASCADE,
            artifact_id TEXT NOT NULL
                REFERENCES artifact_version(artifact_id) ON DELETE RESTRICT,
            container_path TEXT,
            source_path TEXT,
            line_start INTEGER CHECK(line_start IS NULL OR line_start >= 1),
            line_end INTEGER CHECK(line_end IS NULL OR line_end >= 1),
            byte_offset_start INTEGER CHECK(byte_offset_start IS NULL OR byte_offset_start >= 0),
            byte_offset_end INTEGER CHECK(byte_offset_end IS NULL OR byte_offset_end >= 0),
            dex_class TEXT,
            method_signature TEXT,
            resource_name TEXT,
            manifest_xpath TEXT,
            evidence_kind TEXT NOT NULL,
            snippet_redacted TEXT,
            snippet_sha256 TEXT,
            extractor_coordinate_json TEXT NOT NULL DEFAULT '{}',
            CHECK(line_start IS NULL OR line_end IS NULL OR line_end >= line_start),
            CHECK(byte_offset_start IS NULL OR byte_offset_end IS NULL
                  OR byte_offset_end >= byte_offset_start)
        )
        """,
        """
        CREATE TABLE finding_relationship (
            relationship_id TEXT PRIMARY KEY,
            source_finding_id TEXT NOT NULL
                REFERENCES finding(finding_id) ON DELETE CASCADE,
            target_finding_id TEXT NOT NULL
                REFERENCES finding(finding_id) ON DELETE CASCADE,
            relation_type TEXT NOT NULL CHECK(relation_type IN
                ('duplicate_value','same_endpoint','same_vendor','version_change',
                 'corroborates','conflicts','derived_from')),
            confidence REAL CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
            rationale TEXT,
            correlation_rule_id TEXT,
            created_at TEXT NOT NULL,
            CHECK(source_finding_id <> target_finding_id),
            UNIQUE(source_finding_id, target_finding_id, relation_type, correlation_rule_id)
        )
        """,
        """
        CREATE TABLE parser_result (
            parser_result_id TEXT PRIMARY KEY,
            analysis_run_id TEXT NOT NULL
                REFERENCES analysis_run(analysis_run_id) ON DELETE RESTRICT,
            artifact_id TEXT NOT NULL
                REFERENCES artifact_version(artifact_id) ON DELETE RESTRICT,
            parser_id TEXT NOT NULL,
            parser_version TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('success','partial','failed')),
            capabilities_json TEXT NOT NULL DEFAULT '[]',
            output_ref TEXT,
            output_sha256 TEXT,
            diagnostics_json TEXT NOT NULL DEFAULT '[]'
        )
        """,
        """
        CREATE TABLE raw_output (
            raw_output_id TEXT PRIMARY KEY,
            content_sha256 TEXT NOT NULL UNIQUE
                CHECK(length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
            media_type TEXT NOT NULL,
            byte_size INTEGER NOT NULL CHECK(byte_size >= 0),
            relative_object_path TEXT NOT NULL UNIQUE,
            retention_class TEXT NOT NULL DEFAULT 'standard',
            created_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_artifact_app ON artifact_version(app_id, created_at)",
        "CREATE INDEX idx_component_artifact ON bundle_component(artifact_id)",
        "CREATE INDEX idx_observation_run ON acquisition_observation(acquisition_run_id, attempt_no)",
        "CREATE INDEX idx_analysis_artifact ON analysis_run(artifact_id, started_at)",
        "CREATE INDEX idx_execution_run ON analyzer_execution(analysis_run_id, status)",
        "CREATE INDEX idx_finding_artifact ON finding(artifact_id, category)",
        "CREATE INDEX idx_finding_execution ON finding(execution_id)",
        "CREATE INDEX idx_evidence_finding ON evidence_location(finding_id)",
        "CREATE INDEX idx_relationship_source ON finding_relationship(source_finding_id)",
        "CREATE INDEX idx_relationship_target ON finding_relationship(target_finding_id)",
    ),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise EvidenceDatabaseError(f"Value is not JSON serializable: {exc}") from exc


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceDatabaseError(f"{label} must be a non-empty string.")
    return value.strip()


def _sha256(value: object, label: str = "SHA-256") -> str:
    digest = _required_text(value, label).lower()
    if not SHA256_RE.fullmatch(digest):
        raise EvidenceDatabaseError(f"{label} must contain exactly 64 hexadecimal characters.")
    return digest


def _optional_int(value: object, label: str, minimum: int = 0) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceDatabaseError(f"{label} must be an integer >= {minimum}.")
    return value


class EvidenceDatabase:
    """Transactional SQLite store for normalized APK analysis evidence."""

    def __init__(self, workspace: str | Path, *, busy_timeout_ms: int = 10_000):
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms cannot be negative")
        self.root = Path(workspace).expanduser().resolve()
        self.database_dir = self.root / "database"
        self.db_path = self.database_dir / "evidence.sqlite3"
        self.object_root = self.database_dir / "objects"
        self.busy_timeout_ms = busy_timeout_ms

    def _prepare_paths(self) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            if self.database_dir.is_symlink():
                raise EvidenceDatabaseError("Refusing a symlinked database directory.")
            self.database_dir.mkdir(parents=True, exist_ok=True)
            self.database_dir.resolve(strict=True).relative_to(self.root)
            if self.db_path.is_symlink():
                raise EvidenceDatabaseError("Refusing a symlinked evidence database.")
            if self.db_path.exists() and not self.db_path.is_file():
                raise EvidenceDatabaseError("Evidence database path is not a regular file.")
            os.chmod(self.database_dir, 0o700)
        except EvidenceDatabaseError:
            raise
        except (OSError, ValueError) as exc:
            raise EvidenceDatabaseError(f"Cannot prepare evidence database paths: {exc}") from exc

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._prepare_paths()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.db_path,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level="DEFERRED",
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA journal_mode = WAL")
            os.chmod(self.db_path, 0o600)
            yield connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.rollback()
            raise EvidenceDatabaseError(f"SQLite evidence store error: {exc}") from exc
        finally:
            if connection is not None:
                connection.close()

    def ensure(self) -> None:
        """Create the database and apply checksummed migrations atomically."""
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    checksum TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
            connection.commit()
            for version in sorted(MIGRATIONS):
                statements = MIGRATIONS[version]
                checksum = hashlib.sha256("\n".join(statements).encode("utf-8")).hexdigest()
                existing = connection.execute(
                    "SELECT checksum FROM schema_migrations WHERE version = ?",
                    (version,),
                ).fetchone()
                if existing:
                    if existing["checksum"] != checksum:
                        raise EvidenceDatabaseError(
                            f"Migration {version} checksum mismatch; refusing to continue."
                        )
                    continue
                connection.execute("BEGIN IMMEDIATE")
                try:
                    for statement in statements:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO schema_migrations(version, checksum, applied_at) "
                        "VALUES (?, ?, ?)",
                        (version, checksum, utc_now()),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            latest = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
            if latest is None or latest["version"] != SCHEMA_VERSION:
                raise EvidenceDatabaseError(
                    f"Unsupported evidence schema version: {None if latest is None else latest['version']}"
                )

    def schema_version(self) -> int:
        self.ensure()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT MAX(version) AS version FROM schema_migrations"
            ).fetchone()
            return int(row["version"] or 0)

    def create_app_identity(
        self,
        package_id: str,
        *,
        application_label: str | None = None,
        developer_name: str | None = None,
        canonical_app_id: str | None = None,
        acquisition_source: str | None = None,
    ) -> str:
        package_id = _required_text(package_id, "package_id")
        now = utc_now()
        self.ensure()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT app_id, acquisition_sources_json FROM app_identity WHERE package_id = ?",
                (package_id,),
            ).fetchone()
            if row:
                sources = json.loads(row["acquisition_sources_json"])
                if acquisition_source and acquisition_source not in sources:
                    sources.append(acquisition_source)
                connection.execute(
                    """
                    UPDATE app_identity
                    SET application_label = COALESCE(?, application_label),
                        developer_name = COALESCE(?, developer_name),
                        canonical_app_id = COALESCE(?, canonical_app_id),
                        last_seen_at = ?,
                        acquisition_sources_json = ?
                    WHERE app_id = ?
                    """,
                    (
                        application_label, developer_name, canonical_app_id, now,
                        _json(sources), row["app_id"],
                    ),
                )
                connection.commit()
                return str(row["app_id"])
            app_id = str(uuid.uuid4())
            sources = [acquisition_source] if acquisition_source else []
            connection.execute(
                """
                INSERT INTO app_identity(
                    app_id, package_id, canonical_app_id, application_label,
                    developer_name, first_seen_at, last_seen_at, acquisition_sources_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id, package_id, canonical_app_id, application_label, developer_name,
                    now, now, _json(sources),
                ),
            )
            connection.commit()
            return app_id

    def register_artifact(
        self,
        app_id: str,
        apk_sha256: str,
        *,
        package_id: str,
        version_code: int | None = None,
        version_name: str | None = None,
        signer_cert_sha256: Sequence[str] | None = None,
        min_sdk: int | None = None,
        target_sdk: int | None = None,
        acquired_at: str | None = None,
        source_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        app_id = _required_text(app_id, "app_id")
        package_id = _required_text(package_id, "package_id")
        digest = _sha256(apk_sha256)
        version_code = _optional_int(version_code, "version_code")
        min_sdk = _optional_int(min_sdk, "min_sdk")
        target_sdk = _optional_int(target_sdk, "target_sdk")
        signers = [_sha256(item, "signer certificate SHA-256") for item in (signer_cert_sha256 or [])]
        self.ensure()
        with self._connection() as connection:
            app = connection.execute(
                "SELECT package_id FROM app_identity WHERE app_id = ?", (app_id,)
            ).fetchone()
            if app is None:
                raise EvidenceDatabaseError(f"Unknown app identity: {app_id}")
            if app["package_id"] != package_id:
                raise EvidenceDatabaseError("Artifact package_id does not match its app identity.")
            existing = connection.execute(
                """
                SELECT artifact_id, app_id, version_code, version_name,
                       signer_cert_sha256_json
                FROM artifact_version WHERE apk_sha256 = ?
                """,
                (digest,),
            ).fetchone()
            if existing:
                if existing["app_id"] != app_id:
                    raise EvidenceDatabaseError(
                        "This APK digest is already registered to a different app identity."
                    )
                conflicts = (
                    existing["version_code"] is not None and version_code is not None
                    and existing["version_code"] != version_code
                ) or (
                    existing["version_name"] is not None and version_name is not None
                    and existing["version_name"] != version_name
                ) or (
                    json.loads(existing["signer_cert_sha256_json"]) != signers
                    and bool(signers)
                )
                if conflicts:
                    raise EvidenceDatabaseError(
                        "The same APK digest was supplied with conflicting immutable metadata."
                    )
                return str(existing["artifact_id"])
            artifact_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO artifact_version(
                    artifact_id, app_id, package_id, version_code, version_name,
                    apk_sha256, signer_cert_sha256_json, min_sdk, target_sdk,
                    acquired_at, source_id, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id, app_id, package_id, version_code, version_name, digest,
                    _json(signers), min_sdk, target_sdk, acquired_at, source_id,
                    _json(dict(metadata or {})), utc_now(),
                ),
            )
            connection.commit()
            return artifact_id

    def create_acquisition_run(
        self,
        source_adapter_id: str,
        *,
        status: str = "running",
        config_digest: str | None = None,
        manifest_ref: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        source_adapter_id = _required_text(source_adapter_id, "source_adapter_id")
        run_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO acquisition_run(
                    acquisition_run_id, source_adapter_id, started_at, status,
                    config_digest, manifest_ref, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, source_adapter_id, utc_now(), status, config_digest,
                 manifest_ref, _json(dict(metadata or {}))),
            )
            connection.commit()
        return run_id

    def add_bundle_component(
        self,
        acquisition_run_id: str,
        bundle_id: str,
        filename: str,
        *,
        kind: str,
        artifact_id: str | None = None,
        size_bytes: int | None = None,
        expected_hash_algorithm: str | None = None,
        expected_hash: str | None = None,
        actual_sha256: str | None = None,
        verification_status: str = "pending",
        local_object_ref: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        acquisition_run_id = _required_text(acquisition_run_id, "acquisition_run_id")
        bundle_id = _required_text(bundle_id, "bundle_id")
        filename = _required_text(filename, "filename")
        if kind not in {"base_apk", "split_apk", "obb", "asset_pack", "other"}:
            raise EvidenceDatabaseError(f"Unsupported bundle component kind: {kind}")
        size_bytes = _optional_int(size_bytes, "size_bytes")
        if actual_sha256 is not None:
            actual_sha256 = _sha256(actual_sha256, "actual_sha256")
        component_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO bundle_component(
                    component_id, acquisition_run_id, bundle_id, artifact_id,
                    filename, kind, size_bytes, expected_hash_algorithm, expected_hash,
                    actual_sha256, verification_status, local_object_ref, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    component_id, acquisition_run_id, bundle_id, artifact_id, filename,
                    kind, size_bytes, expected_hash_algorithm, expected_hash, actual_sha256,
                    verification_status, local_object_ref, _json(dict(metadata or {})),
                ),
            )
            connection.commit()
        return component_id

    def add_acquisition_observation(
        self,
        acquisition_run_id: str,
        *,
        outcome: str,
        app_id: str | None = None,
        component_id: str | None = None,
        source_uri_redacted: str | None = None,
        expected_digest_algorithm: str | None = None,
        expected_digest: str | None = None,
        actual_sha256: str | None = None,
        requested_at: str | None = None,
        downloaded_at: str | None = None,
        attempt_no: int = 1,
        error_code: str | None = None,
        error_summary: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        attempt_no = _optional_int(attempt_no, "attempt_no", minimum=1)
        if actual_sha256 is not None:
            actual_sha256 = _sha256(actual_sha256, "actual_sha256")
        observation_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            if component_id:
                component = connection.execute(
                    "SELECT acquisition_run_id FROM bundle_component WHERE component_id = ?",
                    (component_id,),
                ).fetchone()
                if component is None or component["acquisition_run_id"] != acquisition_run_id:
                    raise EvidenceDatabaseError(
                        "Acquisition observation component does not belong to the specified run."
                    )
            connection.execute(
                """
                INSERT INTO acquisition_observation(
                    observation_id, acquisition_run_id, app_id, component_id,
                    source_uri_redacted, expected_digest_algorithm, expected_digest,
                    actual_sha256, requested_at, downloaded_at, attempt_no, outcome,
                    error_code, error_summary, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id, acquisition_run_id, app_id, component_id,
                    source_uri_redacted, expected_digest_algorithm, expected_digest,
                    actual_sha256, requested_at, downloaded_at, attempt_no, outcome,
                    error_code, error_summary, _json(dict(metadata or {})),
                ),
            )
            connection.commit()
        return observation_id

    def register_analyzer(
        self,
        analyzer_id: str,
        version: str,
        *,
        categories: Sequence[str] = (),
        input_kinds: Sequence[str] = (),
        required_capabilities: Sequence[str] = (),
        config_schema_version: str | None = None,
        resource_profile: Mapping[str, Any] | None = None,
        default_enabled: bool = False,
    ) -> None:
        analyzer_id = _required_text(analyzer_id, "analyzer_id")
        version = _required_text(version, "version")
        self.ensure()
        with self._connection() as connection:
            definition = (
                _json(list(categories)), _json(list(input_kinds)),
                _json(list(required_capabilities)), config_schema_version,
                _json(dict(resource_profile or {})), int(bool(default_enabled)),
            )
            existing = connection.execute(
                """
                SELECT categories_json, input_kinds_json, required_capabilities_json,
                       config_schema_version, resource_profile_json, default_enabled
                FROM analyzer_definition WHERE analyzer_id = ? AND version = ?
                """,
                (analyzer_id, version),
            ).fetchone()
            if existing:
                if tuple(existing) != definition:
                    raise EvidenceDatabaseError(
                        "Analyzer ID/version is already registered with a different definition."
                    )
                return
            connection.execute(
                """
                INSERT INTO analyzer_definition(
                    analyzer_id, version, categories_json, input_kinds_json,
                    required_capabilities_json, config_schema_version,
                    resource_profile_json, default_enabled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analyzer_id, version) DO NOTHING
                """,
                (
                    analyzer_id, version, _json(list(categories)), _json(list(input_kinds)),
                    _json(list(required_capabilities)), config_schema_version,
                    _json(dict(resource_profile or {})), int(bool(default_enabled)),
                ),
            )
            connection.commit()

    def create_analysis_run(
        self,
        artifact_id: str,
        *,
        requested_analyzers: Sequence[Mapping[str, str]] = (),
        effective_config_digest: str | None = None,
        toolchain_snapshot: Mapping[str, Any] | None = None,
        rule_pack_snapshot: Mapping[str, Any] | None = None,
        runtime_metadata: Mapping[str, Any] | None = None,
    ) -> str:
        run_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO analysis_run(
                    analysis_run_id, artifact_id, started_at, status,
                    requested_analyzers_json, effective_config_digest,
                    toolchain_snapshot_json, rule_pack_snapshot_json, runtime_metadata_json
                ) VALUES (?, ?, ?, 'running', ?, ?, ?, ?, ?)
                """,
                (
                    run_id, artifact_id, utc_now(), _json(list(requested_analyzers)),
                    effective_config_digest, _json(dict(toolchain_snapshot or {})),
                    _json(dict(rule_pack_snapshot or {})), _json(dict(runtime_metadata or {})),
                ),
            )
            connection.commit()
        return run_id

    def record_execution(
        self,
        analysis_run_id: str,
        analyzer_id: str,
        analyzer_version: str,
        *,
        status: str,
        attempt_no: int = 1,
        exit_code: int | None = None,
        timeout_ms: int | None = None,
        output_bytes: int | None = None,
        stdout_ref: str | None = None,
        stderr_ref: str | None = None,
        diagnostics: Sequence[Any] = (),
        metrics: Mapping[str, Any] | None = None,
        config_digest: str | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> str:
        if status not in ALLOWED_EXECUTION_STATUSES:
            raise EvidenceDatabaseError(f"Unsupported analyzer execution status: {status}")
        attempt_no = _optional_int(attempt_no, "attempt_no", minimum=1)
        timeout_ms = _optional_int(timeout_ms, "timeout_ms")
        output_bytes = _optional_int(output_bytes, "output_bytes")
        execution_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO analyzer_execution(
                    execution_id, analysis_run_id, analyzer_id, analyzer_version,
                    attempt_no, started_at, finished_at, status, exit_code, timeout_ms,
                    output_bytes, stdout_ref, stderr_ref, diagnostics_json, metrics_json,
                    config_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution_id, analysis_run_id, analyzer_id, analyzer_version,
                    attempt_no, started_at or utc_now(), finished_at, status, exit_code,
                    timeout_ms, output_bytes, stdout_ref, stderr_ref, _json(list(diagnostics)),
                    _json(dict(metrics or {})), config_digest,
                ),
            )
            connection.commit()
        return execution_id

    def add_finding(
        self,
        execution_id: str,
        artifact_id: str,
        *,
        category: str,
        finding_type: str,
        title: str,
        normalized_value: str | None = None,
        value_fingerprint: str | None = None,
        sensitive: bool = False,
        severity: str | None = None,
        confidence: float | None = None,
        verification_state: str = "static_unverified",
        rationale: str | None = None,
        rule_id: str | None = None,
        rule_version: str | None = None,
        dedup_key: str | None = None,
    ) -> str:
        if verification_state not in ALLOWED_VERIFICATION_STATES:
            raise EvidenceDatabaseError(f"Unsupported verification state: {verification_state}")
        if confidence is not None and (
            isinstance(confidence, bool) or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
        ):
            raise EvidenceDatabaseError("confidence must be between 0 and 1.")
        if sensitive:
            if normalized_value is not None and value_fingerprint is None:
                value_fingerprint = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()
            normalized_value = None
        if value_fingerprint is not None:
            value_fingerprint = _sha256(value_fingerprint, "value_fingerprint")
        finding_id = str(uuid.uuid4())
        now = utc_now()
        self.ensure()
        with self._connection() as connection:
            execution_artifact = connection.execute(
                """
                SELECT ar.artifact_id
                FROM analyzer_execution AS ae
                JOIN analysis_run AS ar ON ar.analysis_run_id = ae.analysis_run_id
                WHERE ae.execution_id = ?
                """,
                (execution_id,),
            ).fetchone()
            if execution_artifact and execution_artifact["artifact_id"] != artifact_id:
                raise EvidenceDatabaseError(
                    "Finding artifact_id must match the artifact analyzed by its execution."
                )
            connection.execute(
                """
                INSERT INTO finding(
                    finding_id, execution_id, artifact_id, category, finding_type,
                    title, normalized_value, value_fingerprint, severity, confidence,
                    verification_state, rationale, rule_id, rule_version,
                    first_seen_at, last_seen_at, dedup_key, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id, execution_id, artifact_id, _required_text(category, "category"),
                    _required_text(finding_type, "finding_type"), _required_text(title, "title"),
                    normalized_value, value_fingerprint, severity, confidence, verification_state,
                    rationale, rule_id, rule_version, now, now, dedup_key, now,
                ),
            )
            connection.commit()
        return finding_id

    def add_evidence_location(
        self,
        finding_id: str,
        artifact_id: str,
        *,
        evidence_kind: str,
        container_path: str | None = None,
        source_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        byte_offset_start: int | None = None,
        byte_offset_end: int | None = None,
        dex_class: str | None = None,
        method_signature: str | None = None,
        resource_name: str | None = None,
        manifest_xpath: str | None = None,
        snippet_redacted: str | None = None,
        snippet_sha256: str | None = None,
        extractor_coordinate: Mapping[str, Any] | None = None,
    ) -> str:
        for label, value in (
            ("line_start", line_start), ("line_end", line_end),
            ("byte_offset_start", byte_offset_start), ("byte_offset_end", byte_offset_end),
        ):
            _optional_int(value, label, minimum=1 if label.startswith("line_") else 0)
        if snippet_sha256 is not None:
            snippet_sha256 = _sha256(snippet_sha256, "snippet_sha256")
        evidence_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            finding = connection.execute(
                "SELECT artifact_id FROM finding WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            if finding and finding["artifact_id"] != artifact_id:
                raise EvidenceDatabaseError(
                    "Evidence location artifact_id must match its finding."
                )
            connection.execute(
                """
                INSERT INTO evidence_location(
                    evidence_id, finding_id, artifact_id, container_path, source_path,
                    line_start, line_end, byte_offset_start, byte_offset_end,
                    dex_class, method_signature, resource_name, manifest_xpath,
                    evidence_kind, snippet_redacted, snippet_sha256, extractor_coordinate_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id, finding_id, artifact_id, container_path, source_path,
                    line_start, line_end, byte_offset_start, byte_offset_end, dex_class,
                    method_signature, resource_name, manifest_xpath,
                    _required_text(evidence_kind, "evidence_kind"), snippet_redacted,
                    snippet_sha256, _json(dict(extractor_coordinate or {})),
                ),
            )
            connection.commit()
        return evidence_id

    def relate_findings(
        self,
        source_finding_id: str,
        target_finding_id: str,
        relation_type: str,
        *,
        confidence: float | None = None,
        rationale: str | None = None,
        correlation_rule_id: str | None = None,
    ) -> str:
        if relation_type not in ALLOWED_RELATION_TYPES:
            raise EvidenceDatabaseError(f"Unsupported finding relationship: {relation_type}")
        if source_finding_id == target_finding_id:
            raise EvidenceDatabaseError("A finding cannot be related to itself.")
        if confidence is not None and (
            isinstance(confidence, bool) or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
        ):
            raise EvidenceDatabaseError("confidence must be between 0 and 1.")
        relationship_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO finding_relationship(
                    relationship_id, source_finding_id, target_finding_id, relation_type,
                    confidence, rationale, correlation_rule_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    relationship_id, source_finding_id, target_finding_id, relation_type,
                    confidence, rationale, correlation_rule_id, utc_now(),
                ),
            )
            connection.commit()
        return relationship_id

    def add_parser_result(
        self,
        analysis_run_id: str,
        artifact_id: str,
        parser_id: str,
        parser_version: str,
        *,
        status: str,
        capabilities: Sequence[str] = (),
        output_ref: str | None = None,
        output_sha256: str | None = None,
        diagnostics: Sequence[Any] = (),
    ) -> str:
        if status not in {"success", "partial", "failed"}:
            raise EvidenceDatabaseError(f"Unsupported parser result status: {status}")
        if output_sha256 is not None:
            output_sha256 = _sha256(output_sha256, "output_sha256")
        parser_result_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            analysis = connection.execute(
                "SELECT artifact_id FROM analysis_run WHERE analysis_run_id = ?",
                (analysis_run_id,),
            ).fetchone()
            if analysis and analysis["artifact_id"] != artifact_id:
                raise EvidenceDatabaseError(
                    "Parser result artifact_id must match its analysis run."
                )
            connection.execute(
                """
                INSERT INTO parser_result(
                    parser_result_id, analysis_run_id, artifact_id, parser_id,
                    parser_version, status, capabilities_json, output_ref,
                    output_sha256, diagnostics_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    parser_result_id, analysis_run_id, artifact_id, parser_id,
                    parser_version, status, _json(list(capabilities)), output_ref,
                    output_sha256, _json(list(diagnostics)),
                ),
            )
            connection.commit()
        return parser_result_id

    def put_raw_output(
        self,
        content: bytes,
        *,
        media_type: str,
        retention_class: str = "standard",
    ) -> str:
        if not isinstance(content, bytes):
            raise EvidenceDatabaseError("Raw output content must be bytes.")
        media_type = _required_text(media_type, "media_type")
        digest = hashlib.sha256(content).hexdigest()
        relative_path = Path("objects") / "sha256" / digest[:2] / digest
        destination = self.object_root / "sha256" / digest[:2] / digest
        try:
            self._prepare_paths()
            for directory in (self.object_root, self.object_root / "sha256", destination.parent):
                if directory.is_symlink():
                    raise EvidenceDatabaseError("Refusing a symlinked evidence object directory.")
                directory.mkdir(parents=True, exist_ok=True)
                directory.resolve(strict=True).relative_to(self.database_dir.resolve(strict=True))
            if destination.is_symlink():
                raise EvidenceDatabaseError("Refusing a symlinked evidence object.")
            if destination.exists():
                if not destination.is_file() or hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                    raise EvidenceDatabaseError("Existing content-addressed object failed integrity check.")
            else:
                fd, temporary_name = tempfile.mkstemp(
                    prefix=".object-", suffix=".tmp", dir=destination.parent
                )
                temporary = Path(temporary_name)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(temporary, 0o600)
                    os.replace(temporary, destination)
                finally:
                    if temporary.exists():
                        temporary.unlink()
        except EvidenceDatabaseError:
            raise
        except (OSError, ValueError) as exc:
            raise EvidenceDatabaseError(f"Cannot publish evidence object: {exc}") from exc

        raw_output_id = str(uuid.uuid4())
        self.ensure()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO raw_output(
                    raw_output_id, content_sha256, media_type, byte_size,
                    relative_object_path, retention_class, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(content_sha256) DO NOTHING
                """,
                (
                    raw_output_id, digest, media_type, len(content),
                    relative_path.as_posix(), retention_class, utc_now(),
                ),
            )
            row = connection.execute(
                "SELECT raw_output_id FROM raw_output WHERE content_sha256 = ?", (digest,)
            ).fetchone()
            connection.commit()
            return str(row["raw_output_id"])

    def list_findings(self, artifact_id: str) -> list[dict[str, Any]]:
        self.ensure()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT f.*, e.analyzer_id, e.analyzer_version
                FROM finding AS f
                JOIN analyzer_execution AS e ON e.execution_id = f.execution_id
                WHERE f.artifact_id = ?
                ORDER BY f.created_at, f.finding_id
                """,
                (artifact_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def integrity_check(self) -> str:
        self.ensure()
        with self._connection() as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            return str(result[0])

    def foreign_key_check(self) -> list[tuple[Any, ...]]:
        self.ensure()
        with self._connection() as connection:
            return [tuple(row) for row in connection.execute("PRAGMA foreign_key_check").fetchall()]
