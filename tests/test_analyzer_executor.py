"""Tests for bounded, process-isolated analyzer execution."""
from __future__ import annotations

import time

import pytest
from pathlib import Path
from threading import Event

from apkworkbench.analysis.contracts import (
    AnalyzerContext,
    AnalyzerDefinition,
    AnalyzerResult,
    Finding,
    ResourceProfile,
)
from apkworkbench.analysis.executor import AnalyzerExecutionError, AnalyzerExecutor
from apkworkbench.analysis.registry import AnalyzerRegistry


def make_context():
    return AnalyzerContext(
        artifact_id="artifact-1",
        artifact_sha256="a" * 64,
        package_id="org.example.app",
        version_code="1",
        artifact_path=Path("/workspace/app.apk"),
        input_kind="apk",
    )


class SuccessfulAnalyzer:
    definition = AnalyzerDefinition(
        "success",
        "1.0",
        ("fixture",),
        ("apk",),
        default_enabled=True,
    )

    def analyze(self, context):
        return AnalyzerResult(
            status="success",
            findings=(
                Finding(
                    category="fixture",
                    finding_type="marker",
                    title="Found marker",
                    normalized_value="marker-value",
                ),
            ),
            metrics={"parsed": 1},
        )


class RaisingAnalyzer:
    definition = AnalyzerDefinition(
        "raises",
        "1.0",
        ("fixture",),
        ("apk",),
        default_enabled=True,
    )

    def analyze(self, context):
        raise RuntimeError("fixture analyzer failure")


class SleepingAnalyzer:
    def __init__(self, timeout=0.1):
        self.definition = AnalyzerDefinition(
            "sleeping",
            "1.0",
            ("fixture",),
            ("apk",),
            resource_profile=ResourceProfile(timeout_seconds=timeout),
        )

    def analyze(self, context):
        time.sleep(2)
        return AnalyzerResult(status="success")


class TooManyFindingsAnalyzer:
    definition = AnalyzerDefinition(
        "many-findings",
        "1.0",
        ("fixture",),
        ("apk",),
        resource_profile=ResourceProfile(max_findings=1),
    )

    def analyze(self, context):
        return AnalyzerResult(
            status="success",
            findings=(
                Finding(category="fixture", finding_type="a", title="A"),
                Finding(category="fixture", finding_type="b", title="B"),
            ),
        )


class LargeOutputAnalyzer:
    definition = AnalyzerDefinition(
        "large-output",
        "1.0",
        ("fixture",),
        ("apk",),
        resource_profile=ResourceProfile(max_output_bytes=100),
    )

    def analyze(self, context):
        return AnalyzerResult(
            status="success",
            findings=(
                Finding(
                    category="fixture",
                    finding_type="large",
                    title="Large finding",
                    rationale="x" * 1000,
                ),
            ),
        )


def test_executor_returns_normalized_success_result():
    outcome = AnalyzerExecutor().execute(SuccessfulAnalyzer(), make_context())

    assert outcome.status == "success"
    assert outcome.exit_code == 0
    assert outcome.result.findings[0].normalized_value == "marker-value"
    assert outcome.result.metrics["parsed"] == 1
    assert outcome.duration_seconds >= 0


def test_analyzer_exception_is_isolated_as_failed_outcome():
    outcome = AnalyzerExecutor().execute(RaisingAnalyzer(), make_context())

    assert outcome.status == "failed"
    assert outcome.result.diagnostics[0].code == "analyzer_exception"
    assert "fixture analyzer failure" in outcome.result.diagnostics[0].message


def test_executor_terminates_analyzer_that_exceeds_wall_clock_limit():
    outcome = AnalyzerExecutor(terminate_grace_seconds=0.1).execute(
        SleepingAnalyzer(timeout=0.1), make_context()
    )

    assert outcome.status == "timed_out"
    assert outcome.result.diagnostics[0].code == "timed_out"


def test_executor_enforces_finding_and_serialized_output_limits():
    finding_outcome = AnalyzerExecutor().execute(TooManyFindingsAnalyzer(), make_context())
    output_outcome = AnalyzerExecutor().execute(LargeOutputAnalyzer(), make_context())

    assert finding_outcome.status == "failed"
    assert finding_outcome.result.diagnostics[0].code == "finding_limit_exceeded"
    assert output_outcome.status == "failed"
    assert output_outcome.result.diagnostics[0].code == "output_limit_exceeded"


def test_execute_plan_continues_after_one_analyzer_fails():
    registry = AnalyzerRegistry()
    registry.register(RaisingAnalyzer())
    registry.register(SuccessfulAnalyzer())

    outcomes = AnalyzerExecutor().execute_plan(registry, make_context())

    assert [item.analyzer_id for item in outcomes] == ["raises", "success"]
    assert [item.status for item in outcomes] == ["failed", "success"]


def test_cancelled_plan_does_not_start_analyzers():
    registry = AnalyzerRegistry()
    registry.register(SuccessfulAnalyzer())
    cancellation = Event()
    cancellation.set()

    outcomes = AnalyzerExecutor().execute_plan(
        registry, make_context(), cancel_event=cancellation
    )

    assert len(outcomes) == 1
    assert outcomes[0].status == "skipped"
    assert outcomes[0].result.diagnostics[0].code == "plan_cancelled"


def test_executor_rejects_missing_capabilities_before_start():
    class CapabilityAnalyzer:
        definition = AnalyzerDefinition(
            "needs-parser",
            "1.0",
            ("fixture",),
            ("apk",),
            required_capabilities=("parsed_manifest",),
        )

        def analyze(self, context):
            return AnalyzerResult(status="success")

    with pytest.raises(AnalyzerExecutionError, match="missing capabilities"):
        AnalyzerExecutor().execute(CapabilityAnalyzer(), make_context())
