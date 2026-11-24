"""Detect external executables and whether their version commands work."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..core.config import Config


@dataclass
class DependencyInfo:
    name: str
    required: bool
    executable: str
    installed: bool = False
    healthy: bool = False
    version: str | None = None
    error: str | None = None

    def __str__(self) -> str:
        if not self.installed:
            status = "MISSING"
        elif not self.healthy:
            status = "UNHEALTHY"
        else:
            status = "OK"
        return f"[{status}] {self.name} ({self.version or 'version unknown'})"


class DependencyDetector:
    CHECKS: ClassVar[dict[str, tuple[bool, list[str]]]] = {
        "playstore-cli": (True, ["--help"]),
        "java": (True, ["-version"]),
        "apktool": (True, ["--version"]),
        "trufflehog": (True, ["--version"]),
        "androguard": (True, ["--help"]),
    }

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

    @staticmethod
    def _resolve_executable(executable: str) -> str | None:
        resolved = shutil.which(executable)
        if resolved:
            return resolved
        candidate_path = Path(executable)
        if candidate_path.is_absolute() or len(candidate_path.parts) > 1:
            return None
        # Console scripts like androguard / playstore-cli live in the active Python
        # environment's bin directory even when the venv is not activated on PATH.
        # Avoid resolving sys.executable itself because venv python symlinks to /usr/bin.
        for bin_dir in (Path(sys.executable).parent, Path(sys.prefix) / "bin"):
            candidate = bin_dir / executable
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    def _check_tool(self, name: str, required: bool, version_args: list[str]) -> DependencyInfo:
        config_name = "playstore_cli" if name == "playstore-cli" else name
        executable = str(self.config.get(f"tools.{config_name}", name))
        info = DependencyInfo(name=name, required=required, executable=executable)
        resolved = self._resolve_executable(executable)
        if not resolved:
            info.error = (
                f"Executable {executable!r} was not found in PATH or the active Python environment."
            )
            return info
        info.installed = True
        try:
            result = subprocess.run(
                [resolved, *version_args], capture_output=True, text=True, timeout=8, check=False
            )
            output = (result.stdout or result.stderr).strip()
            info.version = output.splitlines()[0] if output else None
            info.healthy = result.returncode == 0
            if not info.healthy:
                info.error = f"Version command exited with status {result.returncode}."
        except (OSError, subprocess.TimeoutExpired) as exc:
            info.error = f"Version check failed: {exc}"
        return info

    def detect_all(self) -> list[DependencyInfo]:
        return [
            self._check_tool(name, required, args)
            for name, (required, args) in self.CHECKS.items()
        ]
