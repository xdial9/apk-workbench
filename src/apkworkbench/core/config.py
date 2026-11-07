"""Explicit, deterministic application configuration."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when application configuration is invalid or unreadable."""


class Config:
    """Load defaults and optional YAML overrides without global singleton state."""

    def __init__(
        self,
        config_file: str | Path | None = None,
        *,
        environ: dict[str, str] | None = None,
    ):
        env = os.environ if environ is None else environ
        home = Path(env.get("HOME", str(Path.home()))).expanduser()
        config_dir = Path(
            env.get("APKWORKBENCH_CONFIG_DIR", home / ".config/apkworkbench")
        ).expanduser()
        state_dir = Path(
            env.get("APKWORKBENCH_STATE_DIR", home / ".local/state/apkworkbench")
        ).expanduser()
        workspace = Path(
            env.get("APKWORKBENCH_WORKSPACE", home / "APK-Workbench")
        ).expanduser()

        self.config_file = (
            Path(config_file).expanduser() if config_file else config_dir / "config.yaml"
        )
        self._defaults: dict[str, Any] = {
            "workspace": str(workspace),
            "config_dir": str(config_dir),
            "state_dir": str(state_dir),
            "gpg": {
                "executable": "gpg",
                "homedir": str(state_dir / "gpg"),
                # Published by F-Droid for the admin@f-droid.org OpenPGP key.
                "trusted_fingerprints": [
                    "37D2C98789D8311948394E3E41E7044E1DBA2E89",
                ],
                "timeout_seconds": 30,
            },
            "sources": {
                "fdroid": {
                    "repository_url": "https://f-droid.org/repo",
                    "key_url": (
                        "https://keyserver.ubuntu.com/pks/lookup?op=get&search="
                        "0x37D2C98789D8311948394E3E41E7044E1DBA2E89"
                    ),
                    "signer_fingerprint": "37D2C98789D8311948394E3E41E7044E1DBA2E89",
                    "timeout_seconds": 30,
                    "max_index_bytes": 134217728,
                    "max_signature_bytes": 1048576,
                    "max_key_bytes": 2097152,
                },
            },
            "decompilation": {"timeout_seconds": 3600},\n            "analysis": {"timeout_seconds": 7200},\n            "tools": {
                "gpg": "gpg",
                "java": "java",
                "jadx": "jadx",
                "apktool": "apktool",
                "trufflehog": "trufflehog",
            },
            "logging": {"level": "INFO", "file": "logs/apkworkbench.log"},
        }
        self._data = self.load()

    @staticmethod
    def _merge(defaults: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
        merged = dict(defaults)
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = Config._merge(merged[key], value)
            else:
                merged[key] = value
        return merged

    def load(self) -> dict[str, Any]:
        overrides: dict[str, Any] = {}
        if self.config_file.exists():
            try:
                loaded = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise ConfigError(f"Cannot load {self.config_file}: {exc}") from exc
            if not isinstance(loaded, dict):
                raise ConfigError(
                    f"Configuration root in {self.config_file} must be a mapping."
                )
            overrides = loaded
        self._data = self._merge(self._defaults, overrides)
        return self._data

    def get(self, key: str, default: Any = None) -> Any:
        value: Any = self._data
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
        return value

    def ensure_workspace(self) -> None:
        """Create application-owned workspace directories, not the user's GPG home."""
        root = Path(self.get("workspace")).expanduser()
        for name in (
            "database/run_manifests",
            "downloads",
            "results",
            "reports",
            "logs",
        ):
            (root / name).mkdir(parents=True, exist_ok=True)
        Path(self.get("config_dir")).expanduser().mkdir(parents=True, exist_ok=True)
        Path(self.get("state_dir")).expanduser().mkdir(parents=True, exist_ok=True)
