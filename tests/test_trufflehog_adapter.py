"""Tests for complete TruffleHog objects carried by the analyzer adapter."""
from __future__ import annotations

from pathlib import Path

import pytest

from apkworkbench.analysis.contracts import AnalyzerContext
from apkworkbench.analysis.trufflehog import AnalysisError
from apkworkbench.analysis.trufflehog_adapter import TruffleHogAnalyzer


class FakeScanner:
    timeout_seconds = 60
    max_output_bytes = 1024 * 1024

    def __init__(self, results_root, findings):
        self.results_root = Path(results_root)
        self.findings = findings
        self.calls = []

    def _run_one(self, package_id, version_code, digest, directories):
        self.calls.append((package_id, version_code, digest, directories))
        return self.findings


def make_context(results_root, directories=None):
    return AnalyzerContext(
        artifact_id="artifact-1",
        artifact_sha256="a" * 64,
        package_id="org.example.app",
        version_code="12",
        artifact_path=Path("/workspace/app.apk"),
        input_kind="decompiled_apk",
        capabilities=frozenset({"apktool_output"}),
        parsed_facts={
            "decompilation_dirs": directories
            or [results_root / "org.example.app" / "12" / ("a" * 64) / "apktool"]
        },
    )


def test_adapter_maps_complete_secret_finding_to_common_contract(tmp_path):
    results_root = tmp_path / "results"
    file_path = results_root / "org.example.app" / "12" / ("a" * 64) / "apktool" / "smali" / "Example.smali"
    scanner = FakeScanner(
        results_root,
        [{
            "Verified": True,
            "DetectorName": "ExampleToken",
            "DetectorType": 7,
            "DecoderName": "PLAIN",
            "SourceMetadata": {"Data": {"Filesystem": {"file": str(file_path), "line": 42}}},
            "Raw": "original-secret-value",
            "ExtraData": {"preserve": True},
        }],
    )
    analyzer = TruffleHogAnalyzer(scanner, tool_version="3.90.0")

    result = analyzer.analyze(make_context(results_root))

    assert analyzer.definition.analyzer_id == "trufflehog"
    assert analyzer.definition.version == "3.90.0"
    assert result.status == "success"
    finding = result.findings[0]
    assert finding.category == "secrets"
    assert finding.finding_type == "7"
    assert finding.sensitive is True
    assert finding.raw_data["Raw"] == "original-secret-value"
    assert finding.raw_data["ExtraData"] == {"preserve": True}
    assert len(finding.value_fingerprint) == 64
    assert finding.evidence[0].source_path.endswith("apktool/smali/Example.smali")
    assert finding.evidence[0].line_start == 42
    assert finding.verification_state == "tool_verified"
    assert result.diagnostics[0].code == "credential_verification_enabled"


def test_adapter_rejects_source_path_outside_results_workspace(tmp_path):
    results_root = tmp_path / "results"
    scanner = FakeScanner(
        results_root,
        [{
            "Verified": True,
            "DetectorName": "ExampleToken",
            "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "outside" / "secret.txt"), "line": 1}}},
        }],
    )
    analyzer = TruffleHogAnalyzer(scanner, tool_version="3.90.0")

    with pytest.raises(AnalysisError, match="outside the configured results workspace"):
        analyzer.analyze(make_context(results_root))


def test_adapter_requires_exactly_one_apktool_input(tmp_path):
    scanner = FakeScanner(tmp_path / "results", [])
    analyzer = TruffleHogAnalyzer(scanner, tool_version="3.90.0")
    context = make_context(tmp_path / "results", directories=[])

    with pytest.raises(AnalysisError, match="exactly one decompilation_dirs"):
        analyzer.analyze(context)


def test_adapter_requires_a_real_tool_version(tmp_path):
    scanner = FakeScanner(tmp_path / "results", [])

    with pytest.raises(ValueError, match="detected installed TruffleHog version"):
        TruffleHogAnalyzer(scanner, tool_version="")
