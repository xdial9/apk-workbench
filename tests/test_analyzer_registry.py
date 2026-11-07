"""Tests for analyzer contracts and deterministic planning."""
from __future__ import annotations

from pathlib import Path

import pytest

from apkworkbench.analysis.contracts import (
    AnalyzerContext,
    AnalyzerContractError,
    AnalyzerDefinition,
    AnalyzerDiagnostic,
    AnalyzerResult,
    EvidenceLocation,
    Finding,
    ResourceProfile,
)
from apkworkbench.analysis.registry import AnalyzerRegistry, AnalyzerRegistryError


class FixtureAnalyzer:
    def __init__(self, analyzer_id, *, default_enabled=False, required=(), kinds=("apk",)):
        self.definition = AnalyzerDefinition(
            analyzer_id=analyzer_id,
            version="1.0.0",
            categories=("fixture",),
            input_kinds=kinds,
            required_capabilities=required,
            default_enabled=default_enabled,
        )

    def analyze(self, context):
        return AnalyzerResult(
            status="success",
            findings=(
                Finding(
                    category="fixture",
                    finding_type="fixture_marker",
                    title="Fixture marker",
                    confidence=0.9,
                    evidence=(EvidenceLocation(evidence_kind="test"),),
                ),
            ),
            diagnostics=(AnalyzerDiagnostic(code="FIXTURE", message="Fixture analyzer ran."),),
            metrics={"items_seen": 1},
        )


def test_analyzer_definition_and_resource_profile_are_validated():
    definition = AnalyzerDefinition(
        analyzer_id="manifest",
        version="1.0.0",
        categories=("manifest", "components"),
        input_kinds=("apk", "split_apk"),
        resource_profile=ResourceProfile(timeout_seconds=30, max_output_bytes=1024),
    )

    assert definition.analyzer_id == "manifest"
    assert definition.resource_profile.max_output_bytes == 1024

    with pytest.raises(AnalyzerContractError, match="analyzer_id"):
        AnalyzerDefinition("Manifest", "1.0", ("manifest",), ("apk",))
    with pytest.raises(AnalyzerContractError, match="timeout_seconds"):
        ResourceProfile(timeout_seconds=0)


def test_context_freezes_capabilities_config_and_parsed_facts():
    context = AnalyzerContext(
        artifact_id="artifact-1",
        artifact_sha256="a" * 64,
        package_id="org.example.app",
        version_code="12",
        artifact_path=Path("/workspace/app.apk"),
        input_kind="apk",
        capabilities=frozenset({"manifest"}),
        parsed_facts={"package": "org.example.app"},
        config={"strict": True},
    )

    assert context.artifact_path == Path("/workspace/app.apk")
    with pytest.raises(TypeError):
        context.config["strict"] = False
    with pytest.raises(TypeError):
        context.parsed_facts["package"] = "changed"


def test_sensitive_findings_must_not_expose_raw_values():
    with pytest.raises(AnalyzerContractError, match="Sensitive findings"):
        Finding(
            category="secrets",
            finding_type="token",
            title="Potential token",
            normalized_value="raw-secret",
            sensitive=True,
        )


def test_analyzer_result_rejects_unknown_status_and_accepts_normalized_output():
    analyzer = FixtureAnalyzer("fixture")
    context = AnalyzerContext(
        artifact_id="artifact-1",
        artifact_sha256="a" * 64,
        package_id="org.example.app",
        version_code="1",
        artifact_path=Path("/workspace/app.apk"),
        input_kind="apk",
    )

    result = analyzer.analyze(context)

    assert result.status == "success"
    assert result.findings[0].finding_type == "fixture_marker"
    assert result.metrics["items_seen"] == 1
    with pytest.raises(AnalyzerContractError, match="Unsupported analyzer result status"):
        AnalyzerResult(status="complete")


def test_registry_rejects_duplicate_ids_and_non_analyzers():
    registry = AnalyzerRegistry()
    registry.register(FixtureAnalyzer("manifest"))

    with pytest.raises(AnalyzerRegistryError, match="already registered"):
        registry.register(FixtureAnalyzer("manifest"))
    with pytest.raises(AnalyzerRegistryError, match="AnalyzerDefinition"):
        registry.register(object())


def test_registry_default_plan_is_sorted_and_only_includes_default_enabled():
    registry = AnalyzerRegistry()
    registry.register(FixtureAnalyzer("zeta", default_enabled=True))
    registry.register(FixtureAnalyzer("alpha", default_enabled=True))
    registry.register(FixtureAnalyzer("optional", default_enabled=False))

    plan = registry.plan(input_kind="apk")

    assert [item.definition.analyzer_id for item in plan] == ["alpha", "zeta"]


def test_registry_explicit_plan_preserves_requested_order():
    registry = AnalyzerRegistry()
    registry.register(FixtureAnalyzer("alpha"))
    registry.register(FixtureAnalyzer("beta"))

    plan = registry.plan(input_kind="apk", requested_ids=["beta", "alpha"])

    assert [item.definition.analyzer_id for item in plan] == ["beta", "alpha"]


def test_registry_rejects_unknown_unsupported_and_missing_capability():
    registry = AnalyzerRegistry()
    registry.register(FixtureAnalyzer("manifest", required=("manifest_model",)))
    registry.register(FixtureAnalyzer("dex-only", kinds=("dex",)))

    with pytest.raises(AnalyzerRegistryError, match="Unknown analyzer"):
        registry.plan(input_kind="apk", requested_ids=["missing"])
    with pytest.raises(AnalyzerRegistryError, match="does not accept input kind"):
        registry.plan(input_kind="apk", requested_ids=["dex-only"])
    with pytest.raises(AnalyzerRegistryError, match="missing required capabilities"):
        registry.plan(input_kind="apk", requested_ids=["manifest"])
    assert registry.plan(
        input_kind="apk",
        capabilities={"manifest_model"},
        requested_ids=["manifest"],
    )[0].definition.analyzer_id == "manifest"


def test_registry_can_plan_from_analyzer_context():
    registry = AnalyzerRegistry()
    registry.register(FixtureAnalyzer("manifest", required=("manifest_model",)))
    context = AnalyzerContext(
        artifact_id="artifact-1",
        artifact_sha256="a" * 64,
        package_id="org.example.app",
        version_code="1",
        artifact_path=Path("/workspace/app.apk"),
        input_kind="apk",
        capabilities=frozenset({"manifest_model"}),
    )

    assert len(registry.plan_for_context(context)) == 0
    plan = registry.plan_for_context(context, requested_ids=["manifest"])
    assert plan[0].definition.analyzer_id == "manifest"
