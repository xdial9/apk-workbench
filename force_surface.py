#!/usr/bin/env python3
"""Force re-run surface analysis for eligible artifacts.

This forwards to the CLI's 'surface' command with --force so static surface
analysis re-runs on existing decoded artifacts without triggering new downloads
or decompilations. All state goes through the proper database.
"""
from __future__ import annotations

import sys
from collections.abc import Sequence

from apkworkbench.cli.main import main


def build_force_surface_argv(argv: Sequence[str] | None = None) -> list[str]:
    """Return CLI arguments invoking ``surface`` with ``--force`` enabled."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "surface":
        args = args[1:]
    injected = ["--force"] if "--force" not in args else []
    return ["surface", *injected, *args]


if __name__ == "__main__":
    sys.exit(main(args=build_force_surface_argv()))