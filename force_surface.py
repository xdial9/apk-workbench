#!/usr/bin/env python3
"""Force re-run surface analysis for eligible artifacts.

This forwards to the CLI's 'run' command with --force-decompile --force-analyze
to ensure surface analysis re-runs. All state goes through the proper database.
"""

import sys
from apkworkbench.cli.main import main

if __name__ == "__main__":
    # Surface analysis runs as part of 'run' using the CLI pipeline.
    # Pass all arguments through.
    sys.exit(main())