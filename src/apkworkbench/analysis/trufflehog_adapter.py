"""Adapter exposing the existing safe TruffleHog scanner through the analyzer contract."""
from __future__ import annotations

from pathlib import Path

from apkworkbench.analysis.contracts import (
    AnalyzerContext,
    AnalyzerDefinition,
    AnalyzerDiagnostic,
    AnalyzerResult,
    EvidenceLocation,
    Finding,
    ResourceProfile,
)
from apkworkbench.analysis.trufflehog import AnalysisError, TruffleHogScanner


class TruffleHogAnalyzer:
    """Run the existing local scanner for one artifact and normalize its safe output.

    The installed TruffleHog version is supplied by the caller so execution provenance
    never substitutes an invented or generic version string.
    """

    def __init__(
        self,
        scanner: TruffleHogScanner,
        *,
        tool_version: str,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
    ):
        if not tool_version or not tool_version.strip():
            raise ValueError("tool_version must be the detected installed TruffleHog version.")
        timeout = timeout_seconds or float(scanner.timeout_seconds)
        output_limit = max_output_bytes or min(scanner.max_output_bytes, 64 * 1024 * 1024)
        self.scanner = scanner
        self.definition = AnalyzerDefinition(
            analyzer_id="trufflehog",
            version=tool_version.strip(),
            categories=("secrets",),
            input_kinds=("decompiled_apk",),
            required_capabilities=("jadx_output", "apktool_output"),
            resource_profile=ResourceProfile(
                timeout_seconds=timeout,
                max_output_bytes=output_limit,
                max_findings=100_000,
                max_concurrency=1,
            ),
            default_enabled=False,
            description=(
                "Local TruffleHog filesystem scan of decompiled output; "
                "only explicitly verified findings are retained."
            ),
        )

    def _relative_source_path(self, value: str) -> str | None:
        if not value:
            return None
        path = Path(value)
        try:
            if not path.is_absolute():
                path = self.scanner.results_root / path
            resolved = path.resolve(strict=False)
            return resolved.relative_to(self.scanner.results_root.resolve()).as_posix()
        except (OSError, ValueError):
            raise AnalysisError(
                "TruffleHog reported a source path outside the configured results workspace."
            )

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        raw_directories = context.parsed_facts.get("decompilation_dirs")
        if not isinstance(raw_directories, (list, tuple)) or len(raw_directories) != 2:
            raise AnalysisError(
                "TruffleHog requires exactly two decompilation_dirs: JADX and Apktool."
            )
        directories = [Path(value) for value in raw_directories]
        original_findings = self.scanner._run_one(
            context.package_id,
            context.version_code,
            context.artifact_sha256,
            directories,
        )
        findings = []
        for item in original_findings:
            if item.get("Verified") is not True:
                raise AnalysisError("TruffleHog adapter received a finding that is not explicitly verified.")
            fingerprint = TruffleHogScanner._finding_fingerprint(item)
            detector_name = item.get("DetectorName") or "TruffleHog finding"
            detector_type = item.get("DetectorType") or detector_name
            file_path, line_value = TruffleHogScanner._filesystem_metadata(item)
            source_path = self._relative_source_path(file_path)
            line_number = (
                line_value
                if isinstance(line_value, int) and not isinstance(line_value, bool) and line_value > 0
                else None
            )
            evidence = ()
            if source_path or line_number:
                evidence = (
                    EvidenceLocation(
                        evidence_kind="filesystem_finding",
                        source_path=source_path,
                        line_start=line_number,
                        extractor_coordinate={
                            "decoder_name": item.get("DecoderName"),
                            "verification": "verified",
                        },
                    ),
                )
            findings.append(
                Finding(
                    category="secrets",
                    finding_type=str(detector_type),
                    title=str(detector_name),
                    value_fingerprint=fingerprint,
                    sensitive=True,
                    verification_state="verified",
                    rationale="TruffleHog marked this finding as verified.",
                    rule_id=str(detector_name),
                    rule_version=self.definition.version,
                    dedup_key=fingerprint,
                    evidence=evidence,
                    raw_data=item,
                )
            )
        return AnalyzerResult(
            status="success",
            findings=tuple(findings),
            diagnostics=(
                AnalyzerDiagnostic(
                    code="credential_verification_enabled",
                    message="TruffleHog verification was enabled.",
                    severity="info",
                ),
            ),
            metrics={"finding_count": len(findings)},
        )
