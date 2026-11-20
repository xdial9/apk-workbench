#!/usr/bin/env python3
"""End-to-end pipeline runner that delegates to the proper CLI toolchain.

This script invokes the same code path as 'apkworkbench run' so that every stage
(discovery, download, verification, decompile, surface analysis, scan, report,
reconciliation) updates the database consistently.

Usage:
    python run_pipeline.py          # run the full pipeline
    python run_pipeline.py --package com.example.app   # run for one package
    python run_pipeline.py --help   # all CLI options are forwarded
"""

import sys
from apkworkbench.cli.main import main

if __name__ == "__main__":
    # Forward everything to the real CLI — no bypass, no orphan state.
    sys.exit(main())