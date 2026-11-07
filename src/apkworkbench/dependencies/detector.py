"""Detect external executables and whether their version commands work."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
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
        "gpg": (True, ["--version"]),
        "java": (True, ["-version"]),
        "jadx": (True, ["--version"]),
        "apktool": (True, ["--version"]),
        "trufflehog": (True, ["--version"]),
    }

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

    def _check_tool(self, name: str, required: bool, version_args: list[str]) -> DependencyInfo:
        executable = str(self.config.get(f"tools.{name}", name))
        info = DependencyInfo(name=name, required=required, executable=executable)
        resolved = shutil.which(executable)
        if not resolved:
            info.error = f"Executable {executable!r} was not found in PATH."
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
