"""Process-isolated execution for registered analyzers - hand AI everything.

CAP-FREE: Worker writes full result to disk, parent reads it. No finding/output cap drops data.

The workbench targets Linux. Analyzer code runs in a forked child so the parent can
enforce wall-clock limits and terminate a stuck analyzer without killing the CLI.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass
from threading import Event
from typing import Any

from apkworkbench.analysis.contracts import (
    Analyzer,
    AnalyzerContext,
    AnalyzerDiagnostic,
    AnalyzerResult,
    EvidenceLocation,
    Finding,
    ResourceProfile,
)
from apkworkbench.analysis.registry import AnalyzerRegistry


class AnalyzerExecutionError(RuntimeError):
    """Raised when the executor cannot safely start or supervise an analyzer."""


@dataclass(frozen=True)
class AnalyzerExecutionOutcome:
    analyzer_id: str
    analyzer_version: str
    status: str
    result: AnalyzerResult
    duration_seconds: float
    exit_code: int | None = None


def _result_payload(result: AnalyzerResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "findings": [
            {
                "category": finding.category,
                "finding_type": finding.finding_type,
                "title": finding.title,
                "normalized_value": finding.normalized_value,
                "value_fingerprint": finding.value_fingerprint,
                "sensitive": finding.sensitive,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "verification_state": finding.verification_state,
                "rationale": finding.rationale,
                "rule_id": finding.rule_id,
                "rule_version": finding.rule_version,
                "dedup_key": finding.dedup_key,
                "raw_data": dict(finding.raw_data),
                "evidence": [
                    {
                        "evidence_kind": evidence.evidence_kind,
                        "container_path": evidence.container_path,
                        "source_path": evidence.source_path,
                        "line_start": evidence.line_start,
                        "line_end": evidence.line_end,
                        "byte_offset_start": evidence.byte_offset_start,
                        "byte_offset_end": evidence.byte_offset_end,
                        "dex_class": evidence.dex_class,
                        "method_signature": evidence.method_signature,
                        "resource_name": evidence.resource_name,
                        "manifest_xpath": evidence.manifest_xpath,
                        "snippet_redacted": evidence.snippet_redacted,
                        "snippet_sha256": evidence.snippet_sha256,
                        "extractor_coordinate": dict(evidence.extractor_coordinate),
                    }
                    for evidence in finding.evidence
                ],
            }
            for finding in result.findings
        ],
        "diagnostics": [
            {"code": item.code, "message": item.message, "severity": item.severity}
            for item in result.diagnostics
        ],
        "metrics": dict(result.metrics),
    }


def _result_from_payload(payload: dict[str, Any]) -> AnalyzerResult:
    findings = []
    for item in payload.get("findings", []):
        evidence = tuple(
            EvidenceLocation(**location) for location in item.get("evidence", [])
        )
        finding_fields = {key: value for key, value in item.items() if key != "evidence"}
        findings.append(Finding(**finding_fields, evidence=evidence))
    diagnostics = tuple(
        AnalyzerDiagnostic(**item) for item in payload.get("diagnostics", [])
    )
    return AnalyzerResult(
        status=payload["status"],
        findings=tuple(findings),
        diagnostics=diagnostics,
        metrics=payload.get("metrics", {}),
    )


def _apply_resource_limits(profile: ResourceProfile) -> None:
    if profile.max_memory_mb is None:
        return
    try:
        import resource

        memory_bytes = profile.max_memory_mb * 1024 * 1024
        _current_soft, current_hard = resource.getrlimit(resource.RLIMIT_AS)
        hard_limit = memory_bytes if current_hard < 0 else min(memory_bytes, current_hard)
        resource.setrlimit(resource.RLIMIT_AS, (min(memory_bytes, hard_limit), hard_limit))
    except (ImportError, OSError, ValueError):
        # The parent still enforces wall time and output bounds. A platform that
        # cannot apply RLIMIT_AS must not silently claim that the memory cap applied.
        raise RuntimeError("The configured analyzer memory limit cannot be enforced.")


def _worker_entry(analyzer: Analyzer, context: AnalyzerContext, send_connection, profile, output_path: str) -> None:
    """Worker: run analyzer, write FULL payload to disk, send only tiny ack via pipe.

    CAP-FREE FIX: Old code did two lies:
    - if len(findings) > max_findings: replace whole result with failed + findings=[]
    - if len(encoded) > max_output_bytes: replace whole payload with failed + findings=[]
    Both told AI "no findings" when truth was "too many findings to fit a pipe."
    New: never drop findings for size. Keep all findings, add a warning diagnostic
    if count exceeds profile, write FULL payload to output_path on disk, send b"OK".
    Parent reads file. No truncation, no empty replacement.
    """
    try:
        try:
            _apply_resource_limits(profile)
            result = analyzer.analyze(context)
            if not isinstance(result, AnalyzerResult):
                raise TypeError("Analyzer must return AnalyzerResult.")
            # CAP-FREE: do NOT fail/drop if findings exceed profile. Keep all, warn.
            diagnostics = list(result.diagnostics)
            if len(result.findings) > profile.max_findings:
                diagnostics.append(
                    AnalyzerDiagnostic(
                        code="finding_count_exceeds_profile",
                        message=(
                            f"Analyzer returned {len(result.findings)} findings; "
                            f"profile declares {profile.max_findings}. "
                            f"All findings retained, none dropped."
                        ),
                        severity="warning",
                    )
                )
                result = AnalyzerResult(
                    status=result.status,
                    findings=result.findings,
                    diagnostics=tuple(diagnostics),
                    metrics=result.metrics,
                )
            payload = _result_payload(result)
        except Exception as exc:  # noqa: BLE001 - isolate arbitrary analyzer failures in child
            payload = {
                "status": "failed",
                "findings": [],
                "diagnostics": [{
                    "code": "analyzer_exception",
                    "message": f"{type(exc).__name__}: {str(exc)[:1000]}",
                    "severity": "error",
                }],
                "metrics": {},
            }
        # Write FULL payload to disk - no size cap, no truncation.
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        try:
            send_connection.send_bytes(b"OK")
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001 - worker must not hang parent
        try:
            send_connection.send_bytes(b"FAIL:" + str(exc)[:500].encode("utf-8", "ignore"))
        except Exception:
            pass
    finally:
        try:
            send_connection.close()
        except Exception:
            pass


class AnalyzerExecutor:
    """Execute analyzers in isolated child processes. CAP-FREE: full results via disk, pipe carries only ack."""

    def __init__(self, *, poll_interval: float = 0.05, terminate_grace_seconds: float = 1.0):
        if poll_interval <= 0 or terminate_grace_seconds < 0:
            raise ValueError("Executor polling must be positive and termination grace non-negative.")
        self.poll_interval = poll_interval
        self.terminate_grace_seconds = terminate_grace_seconds

    @staticmethod
    def _terminal_outcome(
        analyzer: Analyzer,
        status: str,
        duration: float,
        code: str,
        message: str,
        exit_code: int | None = None,
    ) -> AnalyzerExecutionOutcome:
        definition = analyzer.definition
        result = AnalyzerResult(
            status=status,
            diagnostics=(AnalyzerDiagnostic(code=code, message=message, severity="error"),),
        )
        return AnalyzerExecutionOutcome(
            definition.analyzer_id,
            definition.version,
            status,
            result,
            duration,
            exit_code,
        )

    def execute(
        self,
        analyzer: Analyzer,
        context: AnalyzerContext,
        *,
        cancel_event: Event | None = None,
    ) -> AnalyzerExecutionOutcome:
        definition = analyzer.definition
        profile = definition.resource_profile
        if context.input_kind not in definition.input_kinds:
            raise AnalyzerExecutionError(
                f"Analyzer {definition.analyzer_id!r} does not accept {context.input_kind!r}."
            )
        missing = sorted(set(definition.required_capabilities) - context.capabilities)
        if missing:
            raise AnalyzerExecutionError(
                f"Analyzer {definition.analyzer_id!r} is missing capabilities: "
                + ", ".join(missing)
            )
        if cancel_event is not None and cancel_event.is_set():
            return self._terminal_outcome(
                analyzer, "cancelled", 0.0, "cancelled_before_start",
                "Execution was cancelled before the analyzer started.",
            )

        try:
            process_context = multiprocessing.get_context("fork")
        except ValueError as exc:
            raise AnalyzerExecutionError(
                "Process-isolated analyzers require a platform with the fork start method."
            ) from exc

        # Temp file on disk for FULL payload - pipe carries only tiny ack.
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="analyzer_exec_", suffix=".json")
        os.close(tmp_fd)
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        receive_connection, send_connection = process_context.Pipe(duplex=False)
        process = process_context.Process(
            target=_worker_entry,
            args=(analyzer, context, send_connection, profile, tmp_path),
            daemon=True,
        )
        started = time.monotonic()
        try:
            process.start()
            send_connection.close()
        except (OSError, RuntimeError) as exc:
            receive_connection.close()
            send_connection.close()
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise AnalyzerExecutionError(f"Cannot start analyzer process: {exc}") from exc

        deadline = started + profile.timeout_seconds
        ack: bytes | None = None
        terminal_status: str | None = None
        terminal_message = ""
        try:
            while process.is_alive():
                if receive_connection.poll(self.poll_interval):
                    try:
                        ack = receive_connection.recv_bytes()
                    except (EOFError, OSError) as exc:
                        terminal_status = "failed"
                        terminal_message = f"Could not read analyzer result: {exc}"
                    break
                if cancel_event is not None and cancel_event.is_set():
                    terminal_status = "cancelled"
                    terminal_message = "Execution was cancelled."
                    break
                if time.monotonic() >= deadline:
                    terminal_status = "timed_out"
                    terminal_message = (
                        f"Analyzer exceeded its {profile.timeout_seconds:g}-second time limit."
                    )
                    break
                process.join(self.poll_interval)

            if terminal_status is not None and process.is_alive():
                process.terminate()
                process.join(self.terminate_grace_seconds)
                if process.is_alive():
                    process.kill()
                    process.join(self.terminate_grace_seconds)
            else:
                process.join(self.terminate_grace_seconds)
                if ack is None and receive_connection.poll():
                    try:
                        ack = receive_connection.recv_bytes()
                    except (EOFError, OSError) as exc:
                        terminal_status = "failed"
                        terminal_message = f"Could not read analyzer result: {exc}"

            duration = time.monotonic() - started
            if terminal_status is not None:
                return self._terminal_outcome(
                    analyzer, terminal_status, duration, terminal_status, terminal_message,
                    process.exitcode,
                )
            if ack is None or not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
                return self._terminal_outcome(
                    analyzer, "failed", duration, "missing_result",
                    "Analyzer process exited without returning a result.", process.exitcode,
                )
            try:
                # Parent reads FULL payload from disk - no size cap.
                with open(tmp_path, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
                result = _result_from_payload(payload)
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                return self._terminal_outcome(
                    analyzer, "failed", duration, "invalid_result",
                    f"Analyzer returned an invalid result payload: {exc}", process.exitcode,
                )
            return AnalyzerExecutionOutcome(
                definition.analyzer_id,
                definition.version,
                result.status,
                result,
                duration,
                process.exitcode,
            )
        finally:
            receive_connection.close()
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            if process.is_alive():
                process.terminate()
                process.join(self.terminate_grace_seconds)
            if process.is_alive():
                process.kill()
                process.join(self.terminate_grace_seconds)
            process.close()

    def execute_plan(
        self,
        registry: AnalyzerRegistry,
        context: AnalyzerContext,
        *,
        requested_ids: Iterable[str] | None = None,
        cancel_event: Event | None = None,
    ) -> tuple[AnalyzerExecutionOutcome, ...]:
        """Run a validated plan sequentially; one analyzer failure does not stop others."""
        plan = registry.plan_for_context(context, requested_ids=requested_ids)
        outcomes: list[AnalyzerExecutionOutcome] = []
        for index, analyzer in enumerate(plan):
            if cancel_event is not None and cancel_event.is_set():
                for remaining in plan[index:]:
                    outcomes.append(
                        self._terminal_outcome(
                            remaining, "skipped", 0.0, "plan_cancelled",
                            "Analyzer was not started because the plan was cancelled.",
                        )
                    )
                break
            outcomes.append(self.execute(analyzer, context, cancel_event=cancel_event))
        return tuple(outcomes)
