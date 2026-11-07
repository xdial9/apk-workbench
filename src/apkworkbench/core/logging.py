"""Logging setup for CLI and library use."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from .config import Config


def setup_logging(config: Config | None = None) -> logging.Logger:
    config = config or Config()
    config.ensure_workspace()
    level_name = str(config.get("logging.level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_path = Path(config.get("workspace")) / config.get("logging.file", "logs/apkworkbench.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("apkworkbench")
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(console)
        logger.addHandler(file_handler)
    return logger
