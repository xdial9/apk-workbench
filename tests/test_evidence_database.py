"""Tests for the normalized SQLite evidence store."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from apkworkbench.database import evidence as evidence_module
from apkworkbench.database.evidence import EvidenceDatabase, EvidenceDatabaseError


APK_HASH = "a" * 64
SIGNER_HASH = "b" * 64


def seed_analysis(database: EvidenceDatabase, tmp_path):
    app_id = database.create_app_identity(
        "org.example.app", application_label="Example", acquisition_source="google_play"
    )
    artifact_id = database.register_artifact(
        app_id,
        APK_HASH,
        package_id="org.example.app",
        version_code=12,
        version_name="1.2",
        signer_cert_sha256=[SIGNER_HASH],
        min_sdk=23,
        target_sdk=35,
    )
    database.register_analyzer(
        "manifest", "1.0.0", categories=["manifest"], input_kinds=["apk"]
    )
    analysis_id = database.create_analysis_run(
        artifact_id,
        requested_analyzers=[{"id": "manifest", "version": "1.0.0"}],
    )
    execution_id = database.record_execution(
        analysis_id, "manifest", "1.0.0", status="success", output_bytes=42
    )
    return app_id, artifact_id, analysis_id, execution_id


def test_ensure_applies_versioned_schema_and_enables_integrity(tmp_path):
    database = EvidenceDatabase(tmp_path)

    database.ensure()

    assert database.schema_version() == 1
    assert database.integrity_check() == "ok"
    assert database.foreign_key_check() == []
    with sqlite3.connect(database.db_path) as connection:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {
        "schema_migrations",
        "app_identity",
        "artifact_version",
        "acquisition_run",
        "bundle_component",
        "acquisition_observation",
        "analysis_run",
        "analyzer_definition",
        "analyzer_execution",
        "finding",
        "evidence_location",
        "finding_relationship",
        "parser_result",
        "raw_output",
    } <= names


def test_app_identity_is_idempotent_and_accumulates_sources(tmp_path):
    database = EvidenceDatabase(tmp_path)

    first = database.create_app_identity(
        "org.example.app", application_label="Example", acquisition_source="google_play"
    )
    second = database.create_app_identity(
        "org.example.app", developer_name="Example Inc", acquisition_source="fdroid"
    )

    assert first == second
    with sqlite3.connect(database.db_path) as connection:
        row = connection.execute(
            "SELECT application_label, developer_name, acquisition_sources_json "
            "FROM app_identity WHERE app_id = ?",
            (first,),
        ).fetchone()
    assert row[0] == "Example"
    assert row[1] == "Example Inc"
    assert json.loads(row[2]) == ["google_play", "fdroid"]


def test_artifact_registration_is_content_addressed_and_immutable(tmp_path):
    database = EvidenceDatabase(tmp_path)
    app_id = database.create_app_identity("org.example.app")
    first = database.register_artifact(
        app_id, APK_HASH, package_id="org.example.app", version_code=12
    )
    second = database.register_artifact(
        app_id, APK_HASH, package_id="org.example.app", version_code=12
    )

    assert first == second
    with pytest.raises(EvidenceDatabaseError, match="64 hexadecimal"):
        database.register_artifact(
            app_id, "not-a-hash", package_id="org.example.app"
        )
    with pytest.raises(EvidenceDatabaseError, match="does not match"):
        database.register_artifact(
            app_id, "c" * 64, package_id="org.other.app"
        )


def test_acquisition_bundle_and_observation_are_linked(tmp_path):
    database = EvidenceDatabase(tmp_path)
    app_id = database.create_app_identity("org.example.app")
    run_id = database.create_acquisition_run("google_play")
    component_id = database.add_bundle_component(
        run_id,
        "bundle-1",
        "base.apk",
        kind="base_apk",
        size_bytes=100,
        actual_sha256=APK_HASH,
        verification_status="verified",
    )
    observation_id = database.add_acquisition_observation(
        run_id,
        app_id=app_id,
        component_id=component_id,
        outcome="downloaded",
        actual_sha256=APK_HASH,
        attempt_no=1,
    )

    assert run_id
    assert component_id
    assert observation_id
    assert database.foreign_key_check() == []


def test_findings_and_precise_evidence_locations_round_trip(tmp_path):
    database = EvidenceDatabase(tmp_path)
    _, artifact_id, _, execution_id = seed_analysis(database, tmp_path)
    finding_id = database.add_finding(
        execution_id,
        artifact_id,
        category="manifest",
        finding_type="exported_component",
        title="Exported activity",
        normalized_value="org.example.app.DeepLinkActivity",
        confidence=0.92,
        rationale="Activity is exported and has an intent filter.",
        rule_id="manifest.exported_activity",
        rule_version="1",
    )
    evidence_id = database.add_evidence_location(
        finding_id,
        artifact_id,
        evidence_kind="manifest_attribute",
        container_path="AndroidManifest.xml",
        manifest_xpath="/manifest/application/activity[1]/@android:exported",
        line_start=18,
        line_end=18,
        snippet_redacted='android:exported="true"',
    )

    findings = database.list_findings(artifact_id)
    assert len(findings) == 1
    assert findings[0]["finding_id"] == finding_id
    assert findings[0]["analyzer_id"] == "manifest"
    assert findings[0]["confidence"] == pytest.approx(0.92)
    with sqlite3.connect(database.db_path) as connection:
        evidence = connection.execute(
            "SELECT evidence_id, container_path, line_start, manifest_xpath "
            "FROM evidence_location WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
    assert evidence == (
        evidence_id,
        "AndroidManifest.xml",
        18,
        "/manifest/application/activity[1]/@android:exported",
    )


def test_sensitive_finding_never_persists_the_original_value(tmp_path):
    database = EvidenceDatabase(tmp_path)
    _, artifact_id, _, execution_id = seed_analysis(database, tmp_path)
    secret = "example-private-token-value"
    finding_id = database.add_finding(
        execution_id,
        artifact_id,
        category="secrets",
        finding_type="api_token",
        title="Potential embedded token",
        normalized_value=secret,
        sensitive=True,
    )

    with sqlite3.connect(database.db_path) as connection:
        value, fingerprint = connection.execute(
            "SELECT normalized_value, value_fingerprint FROM finding WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
    assert value is None
    assert fingerprint == hashlib.sha256(secret.encode("utf-8")).hexdigest()


def test_finding_relationships_are_typed_and_self_links_rejected(tmp_path):
    database = EvidenceDatabase(tmp_path)
    _, artifact_id, _, execution_id = seed_analysis(database, tmp_path)
    first = database.add_finding(
        execution_id, artifact_id, category="endpoint", finding_type="url", title="Endpoint A"
    )
    second = database.add_finding(
        execution_id, artifact_id, category="endpoint", finding_type="url", title="Endpoint B"
    )

    relationship_id = database.relate_findings(
        first, second, "same_endpoint", confidence=0.8, rationale="Normalized hosts match."
    )

    assert relationship_id
    with pytest.raises(EvidenceDatabaseError, match="cannot be related to itself"):
        database.relate_findings(first, first, "same_endpoint")


def test_parser_result_and_raw_outputs_are_versioned_and_deduplicated(tmp_path):
    database = EvidenceDatabase(tmp_path)
    _, artifact_id, analysis_id, _ = seed_analysis(database, tmp_path)
    raw = b'{"parser":"fixture","status":"ok"}'
    first = database.put_raw_output(raw, media_type="application/json")
    second = database.put_raw_output(raw, media_type="application/json")

    assert first == second
    parser_id = database.add_parser_result(
        analysis_id,
        artifact_id,
        "zip-apk",
        "1.0.0",
        status="success",
        capabilities=["zip", "manifest"],
        output_sha256=hashlib.sha256(raw).hexdigest(),
    )
    assert parser_id
    objects = list((tmp_path / "database" / "objects").rglob("*"))
    object_files = [path for path in objects if path.is_file()]
    assert len(object_files) == 1
    assert object_files[0].read_bytes() == raw


def test_execution_requires_registered_analyzer_and_valid_status(tmp_path):
    database = EvidenceDatabase(tmp_path)
    _, artifact_id, analysis_id, _ = seed_analysis(database, tmp_path)

    with pytest.raises(sqlite3.IntegrityError):
        database.record_execution(
            analysis_id, "missing", "1.0", status="success"
        )
    with pytest.raises(EvidenceDatabaseError, match="Unsupported analyzer execution status"):
        database.record_execution(
            analysis_id, "manifest", "1.0.0", status="unknown"
        )
    assert database.integrity_check() == "ok"


def test_migration_checksum_mismatch_fails_closed(tmp_path, monkeypatch):
    database = EvidenceDatabase(tmp_path)
    database.ensure()
    altered = evidence_module.MIGRATIONS[1] + ("-- unexpected migration edit",)
    monkeypatch.setitem(evidence_module.MIGRATIONS, 1, altered)

    with pytest.raises(EvidenceDatabaseError, match="checksum mismatch"):
        database.ensure()


def test_database_refuses_symlinked_database_directory(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "database").symlink_to(outside, target_is_directory=True)

    with pytest.raises(EvidenceDatabaseError, match="symlinked database directory"):
        EvidenceDatabase(workspace).ensure()
