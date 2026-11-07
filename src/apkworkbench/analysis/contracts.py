"""Stable contracts shared by built-in APK analyzers."""
from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol


ANALYZER_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESULT_STATUSES = {"success", "partial", "skipped", "failed", "timed_out", "cancelled"}
VERIFICATION_STATES = {
    "static_unverified", "corroborated_static", "tool_verified", "manually_verified",
    "runtime_verified", "rejected",
}


class AnalyzerContractError(ValueError):
    """Raised when an analyzer definition or result violates the shared contract."""


@dataclass(frozen=True)
class ResourceProfile:
    timeout_seconds: float = 120.0
    max_output_bytes: int = 5_000_000
    max_findings: int = 100_000
    max_memory_mb: int | None = None
    max_concurrency: int = 1

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise AnalyzerContractError("timeout_seconds must be positive.")
        for name in ("max_output_bytes", "max_findings", "max_concurrency"):
            if getattr(self, name) < 1:
                raise AnalyzerContractError(f"{name} must be at least 1.")
        if self.max_memory_mb is not None and self.max_memory_mb < 1:
            raise AnalyzerContractError("max_memory_mb must be at least 1 when supplied.")


@dataclass(frozen=True)
class AnalyzerDefinition:
    analyzer_id: str
    version: str
    categories: tuple[str, ...]
    input_kinds: tuple[str, ...]
    required_capabilities: tuple[str, ...] = ()
    config_schema_version: str = "1"
    resource_profile: ResourceProfile = field(default_factory=ResourceProfile)
    default_enabled: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not ANALYZER_ID_RE.fullmatch(self.analyzer_id):
            raise AnalyzerContractError(
                "analyzer_id must be 2-64 lowercase letters, digits, dots, underscores or hyphens."
            )
        if not self.version.strip():
            raise AnalyzerContractError("Analyzer version must be non-empty.")
        if not self.input_kinds or any(not item.strip() for item in self.input_kinds):
            raise AnalyzerContractError("At least one non-empty input kind is required.")
        if any(not item.strip() for item in self.categories):
            raise AnalyzerContractError("Analyzer categories cannot contain empty values.")
        if len(set(self.input_kinds)) != len(self.input_kinds):
            raise AnalyzerContractError("Analyzer input kinds must be unique.")
        if len(set(self.categories)) != len(self.categories):
            raise AnalyzerContractError("Analyzer categories must be unique.")


@dataclass(frozen=True)
class EvidenceLocation:
    evidence_kind: str
    container_path: str | None = None
    source_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    byte_offset_start: int | None = None
    byte_offset_end: int | None = None
    dex_class: str | None = None
    method_signature: str | None = None
    resource_name: str | None = None
    manifest_xpath: str | None = None
    snippet_redacted: str | None = None
    snippet_sha256: str | None = None
    extractor_coordinate: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_kind.strip():
            raise AnalyzerContractError("evidence_kind must be non-empty.")
        for name in ("line_start", "line_end"):
            value = getattr(self, name)
            if value is not None and value < 1:
                raise AnalyzerContractError(f"{name} must be at least 1.")
        for name in ("byte_offset_start", "byte_offset_end"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise AnalyzerContractError(f"{name} cannot be negative.")
        if (
            self.line_start is not None and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise AnalyzerContractError("line_end cannot precede line_start.")
        if (
            self.byte_offset_start is not None and self.byte_offset_end is not None
            and self.byte_offset_end < self.byte_offset_start
        ):
            raise AnalyzerContractError("byte_offset_end cannot precede byte_offset_start.")
        if self.snippet_sha256 is not None and not SHA256_RE.fullmatch(self.snippet_sha256):
            raise AnalyzerContractError("snippet_sha256 must be a lowercase SHA-256 digest.")
        object.__setattr__(
            self, "extractor_coordinate", MappingProxyType(dict(self.extractor_coordinate))
        )


@dataclass(frozen=True)
class Finding:
    category: str
    finding_type: str
    title: str
    normalized_value: str | None = None
    value_fingerprint: str | None = None
    sensitive: bool = False
    severity: str | None = None
    confidence: float | None = None
    verification_state: str = "static_unverified"
    rationale: str | None = None
    rule_id: str | None = None
    rule_version: str | None = None
    dedup_key: str | None = None
    evidence: tuple[EvidenceLocation, ...] = ()
    raw_data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_data", MappingProxyType(dict(self.raw_data)))
        for name in ("category", "finding_type", "title"):
            if not getattr(self, name).strip():
                raise AnalyzerContractError(f"{name} must be non-empty.")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise AnalyzerContractError("confidence must be between 0 and 1.")
        if self.verification_state not in VERIFICATION_STATES:
            raise AnalyzerContractError(
                f"Unsupported verification_state: {self.verification_state}"
            )
        if self.value_fingerprint is not None and not SHA256_RE.fullmatch(
            self.value_fingerprint
        ):
            raise AnalyzerContractError("value_fingerprint must be a lowercase SHA-256 digest.")


@dataclass(frozen=True)
class AnalyzerDiagnostic:
    code: str
    message: str
    severity: str = "warning"

    def __post_init__(self) -> None:
        if not self.code.strip() or not self.message.strip():
            raise AnalyzerContractError("Diagnostic code and message must be non-empty.")


@dataclass(frozen=True)
class AnalyzerContext:
    artifact_id: str
    artifact_sha256: str
    package_id: str
    version_code: str
    artifact_path: Path
    input_kind: str
    capabilities: frozenset[str] = frozenset()
    parsed_facts: Mapping[str, Any] = field(default_factory=dict)
    config: Mapping[str, Any] = field(default_factory=dict)
    output_dir: Path | None = None
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger("apkworkbench.analysis")
    )

    def __post_init__(self) -> None:
        if not SHA256_RE.fullmatch(self.artifact_sha256):
            raise AnalyzerContractError("artifact_sha256 must be a lowercase SHA-256 digest.")
        for name in ("artifact_id", "package_id", "version_code", "input_kind"):
            if not getattr(self, name).strip():
                raise AnalyzerContractError(f"{name} must be non-empty.")
        object.__setattr__(self, "artifact_path", Path(self.artifact_path))
        if self.output_dir is not None:
            object.__setattr__(self, "output_dir", Path(self.output_dir))
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        object.__setattr__(self, "parsed_facts", MappingProxyType(dict(self.parsed_facts)))
        object.__setattr__(self, "config", MappingProxyType(dict(self.config)))


@dataclass(frozen=True)
class AnalyzerResult:
    status: str
    findings: tuple[Finding, ...] = ()
    diagnostics: tuple[AnalyzerDiagnostic, ...] = ()
    metrics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in RESULT_STATUSES:
            raise AnalyzerContractError(f"Unsupported analyzer result status: {self.status}")
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "metrics", MappingProxyType(dict(self.metrics)))


class Analyzer(Protocol):
    """Protocol implemented by a registered analyzer."""

    definition: AnalyzerDefinition

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        """Analyze one immutable artifact context and return normalized findings."""
