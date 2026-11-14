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
