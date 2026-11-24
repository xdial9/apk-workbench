from __future__ import annotations

import pytest

from apkworkbench.core.config import Config, ConfigError


def test_unsupported_source_and_tool_overrides_are_discarded(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "sources:\n  obsolete_source:\n    endpoint: https://invalid.example\n"
        "tools:\n  obsolete_tool: old-tool\n  jadx: /opt/jadx\n"
        "  apktool: /opt/apktool-wrapper\n",
        encoding="utf-8",
    )

    config = Config(config_file, environ={"HOME": str(tmp_path)})

    assert config.get("sources") == {"google_play": {"retry_backoff_seconds": 1.0, "auth_mode": "auto"}}
    assert config.get("tools.obsolete_tool") is None
    assert config.get("tools.jadx") is None
    assert config.get("tools.apktool") == "/opt/apktool-wrapper"


def test_default_workspace_is_within_checkout(tmp_path):
    config = Config(environ={"HOME": str(tmp_path)})

    assert config.get("workspace") == str(tmp_path / "APK-Workbench" / "workspace")


def test_invalid_auth_mode_is_rejected(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "sources:\n  google_play:\n    auth_mode: wrong-mode\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="auth_mode"):
        Config(config_file, environ={"HOME": str(tmp_path)})


def test_auth_mode_value_is_normalized(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "sources:\n  google_play:\n    auth_mode: ACCOUNT\n",
        encoding="utf-8",
    )

    config = Config(config_file, environ={"HOME": str(tmp_path)})

    assert config.get("sources.google_play.auth_mode") == "account"


def test_androguard_timeout_default_and_override(tmp_path):
    default_config = Config(environ={"HOME": str(tmp_path)})
    assert default_config.get("analysis.androguard_timeout_seconds") == 1800

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "analysis:\n  androguard_timeout_seconds: 900\n",
        encoding="utf-8",
    )
    overridden = Config(config_file, environ={"HOME": str(tmp_path)})
    assert overridden.get("analysis.androguard_timeout_seconds") == 900
    assert overridden.get("analysis.timeout_seconds") == 7200


def test_config_preserves_other_configured_sources_in_defaults(tmp_path):
    class MultiSourceConfig(Config):
        def __init__(self, config_file, *, environ):
            self.config_file = config_file
            self._defaults = {
                "workspace": str(tmp_path / "workspace"),
                "config_dir": str(tmp_path / "config"),
                "state_dir": str(tmp_path / "state"),
                "sources": {
                    "google_play": {"retry_backoff_seconds": 1.0, "auth_mode": "auto"},
                    "custom_mirror": {"enabled": False, "url": "https://default.example"},
                },
                "decompilation": {"timeout_seconds": 3600},
                "analysis": {
                    "timeout_seconds": 7200,
                    "androguard_timeout_seconds": 1800,
                    "max_output_bytes": 536870912,
                },
                "tools": {
                    "playstore_cli": "playstore-cli",
                    "java": "java",
                    "apktool": "apktool",
                    "trufflehog": "trufflehog",
                },
                "logging": {"level": "INFO", "file": "logs/apkworkbench.log"},
            }
            self._data = self.load()

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "sources:\n"
        "  custom_mirror:\n"
        "    enabled: true\n"
        "  obsolete_source:\n"
        "    endpoint: https://invalid.example\n",
        encoding="utf-8",
    )

    config = MultiSourceConfig(config_file, environ={"HOME": str(tmp_path)})
    assert config.get("sources.custom_mirror") == {
        "enabled": True,
        "url": "https://default.example",
    }
    assert config.get("sources.google_play.auth_mode") == "auto"
    assert config.get("sources.obsolete_source") is None


def test_detector_resolves_androguard_from_python_env_when_not_on_path(monkeypatch, tmp_path):
    from apkworkbench.dependencies.detector import DependencyDetector

    config = Config(environ={"HOME": str(tmp_path)})
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    detector = DependencyDetector(config)
    checks = {item.name: item for item in detector.detect_all()}
    androguard_info = checks["androguard"]
    assert androguard_info.installed is True
    assert androguard_info.healthy is True
    assert androguard_info.error is None

    monkeypatch.setattr(
        "apkworkbench.dependencies.detector.shutil.which", lambda _exe: None
    )
    fake_bin = tmp_path / "fakevenv" / "bin"
    fake_bin.mkdir(parents=True)
    monkeypatch.setattr(
        "apkworkbench.dependencies.detector.sys.executable",
        str(fake_bin / "python"),
    )
    monkeypatch.setattr(
        "apkworkbench.dependencies.detector.sys.prefix",
        str(tmp_path / "fakevenv"),
    )
    missing_info = detector._check_tool("androguard", True, ["--help"])
    assert missing_info.installed is False
    assert missing_info.healthy is False
    assert "not found" in (missing_info.error or "")
