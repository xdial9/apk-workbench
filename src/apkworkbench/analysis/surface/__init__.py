"""Surface analyzer overhaul package (plan v2, ai-memory/surface-plan-v2.md).

Public facade keeps the established entry points stable while the internals
move into this package across Phase S:
    analyze_apk_surface, run_static_surface_analysis — unchanged signatures.

NOTE: resolved lazily to avoid an import cycle (apk_surface imports
surface.classify at module load; the facade must not import apk_surface
eagerly).
"""
from __future__ import annotations

from typing import Any

_LAZY = ("analyze_apk_surface", "run_static_surface_analysis")


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from apkworkbench.analysis import apk_surface as _apk_surface

        return getattr(_apk_surface, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_LAZY)