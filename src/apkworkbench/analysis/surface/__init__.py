"""Surface analyzer overhaul package (plan v2, ai-memory/surface-plan-v2.md).

Public facade keeps the established entry points stable while the internals
move into this package across Phase S:
    analyze_apk_surface, run_static_surface_analysis — unchanged signatures.
"""
from __future__ import annotations

from apkworkbench.analysis.apk_surface import (
    analyze_apk_surface,
    run_static_surface_analysis,
)

__all__ = ["analyze_apk_surface", "run_static_surface_analysis"]
