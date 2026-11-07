"""Deterministic registry and capability planner for built-in analyzers."""
from __future__ import annotations

from collections.abc import Iterable

from apkworkbench.analysis.contracts import (
    Analyzer,
    AnalyzerDefinition,
    AnalyzerContext,
)


class AnalyzerRegistryError(ValueError):
    """Raised when analyzer registration or planning is invalid."""


class AnalyzerRegistry:
    """Register one active version of each analyzer ID and build execution plans."""

    def __init__(self) -> None:
        self._analyzers: dict[str, Analyzer] = {}

    def register(self, analyzer: Analyzer) -> None:
        definition = getattr(analyzer, "definition", None)
        if not isinstance(definition, AnalyzerDefinition):
            raise AnalyzerRegistryError(
                "Registered analyzers must expose an AnalyzerDefinition as .definition."
            )
        if not callable(getattr(analyzer, "analyze", None)):
            raise AnalyzerRegistryError("Registered analyzers must implement analyze(context).")
        if definition.analyzer_id in self._analyzers:
            existing = self._analyzers[definition.analyzer_id].definition
            raise AnalyzerRegistryError(
                f"Analyzer {definition.analyzer_id!r} is already registered "
                f"at version {existing.version!r}."
            )
        self._analyzers[definition.analyzer_id] = analyzer

    def get(self, analyzer_id: str) -> Analyzer:
        try:
            return self._analyzers[analyzer_id]
        except KeyError as exc:
            raise AnalyzerRegistryError(f"Unknown analyzer: {analyzer_id}") from exc

    def definitions(self) -> tuple[AnalyzerDefinition, ...]:
        return tuple(
            self._analyzers[key].definition for key in sorted(self._analyzers)
        )

    def plan(
        self,
        *,
        input_kind: str,
        capabilities: Iterable[str] = (),
        requested_ids: Iterable[str] | None = None,
    ) -> tuple[Analyzer, ...]:
        """Return analyzers in deterministic order after validating requirements.

        If requested_ids is omitted, only default-enabled analyzers are selected.
        An explicitly requested analyzer that cannot run fails planning rather than
        being silently skipped.
        """
        available = frozenset(capabilities)
        if requested_ids is None:
            selected_ids = [
                definition.analyzer_id
                for definition in self.definitions()
                if definition.default_enabled
            ]
        else:
            selected_ids = list(requested_ids)
            if len(set(selected_ids)) != len(selected_ids):
                raise AnalyzerRegistryError("requested_ids contains duplicate analyzer IDs.")

        planned: list[Analyzer] = []
        for analyzer_id in selected_ids:
            analyzer = self.get(analyzer_id)
            definition = analyzer.definition
            if input_kind not in definition.input_kinds:
                raise AnalyzerRegistryError(
                    f"Analyzer {analyzer_id!r} does not accept input kind {input_kind!r}."
                )
            missing = sorted(set(definition.required_capabilities) - available)
            if missing:
                raise AnalyzerRegistryError(
                    f"Analyzer {analyzer_id!r} is missing required capabilities: "
                    + ", ".join(missing)
                )
            planned.append(analyzer)
        return tuple(planned)

    def plan_for_context(
        self,
        context: AnalyzerContext,
        *,
        requested_ids: Iterable[str] | None = None,
    ) -> tuple[Analyzer, ...]:
        return self.plan(
            input_kind=context.input_kind,
            capabilities=context.capabilities,
            requested_ids=requested_ids,
        )

    def __len__(self) -> int:
        return len(self._analyzers)
