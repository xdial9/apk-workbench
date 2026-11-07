"""Deterministic SHA-256-based selection of new F-Droid APK binaries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..sources.fdroid import FdroidArtifact


@dataclass(frozen=True)
class SelectionResult:
    artifacts: tuple[FdroidArtifact, ...]
    requested: int
    shortfall: int

    @property
    def selected_count(self) -> int:
        return len(self.artifacts)


def select_new_artifacts(
    artifacts: Iterable[FdroidArtifact],
    previously_downloaded_hashes: set[str],
    apk_count: int,
    *,
    package_filter: str | None = None,
) -> SelectionResult:
    """Select up to N distinct binaries, newest version first within each package."""
    if apk_count < 1:
        raise ValueError("apk_count must be at least 1")

    by_package: dict[str, list[FdroidArtifact]] = {}
    for artifact in artifacts:
        if package_filter and artifact.package_id != package_filter:
            continue
        by_package.setdefault(artifact.package_id, []).append(artifact)

    ordered: list[FdroidArtifact] = []
    for package_id in sorted(by_package):
        ordered.extend(
            sorted(
                by_package[package_id],
                key=lambda item: (-item.version_code, item.sha256),
            )
        )

    seen_hashes = {item.lower() for item in previously_downloaded_hashes}
    selected: list[FdroidArtifact] = []
    for artifact in ordered:
        digest = artifact.sha256.lower()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        selected.append(artifact)
        if len(selected) == apk_count:
            break

    return SelectionResult(
        artifacts=tuple(selected),
        requested=apk_count,
        shortfall=max(0, apk_count - len(selected)),
    )
