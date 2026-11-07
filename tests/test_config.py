from __future__ import annotations

from apkworkbench.core.config import Config


def test_unsupported_source_and_tool_overrides_are_discarded(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "sources:\n  obsolete_source:\n    endpoint: https://invalid.example\n"
        "tools:\n  obsolete_tool: old-tool\n  jadx: /opt/jadx\n",
        encoding="utf-8",
    )

    config = Config(config_file, environ={"HOME": str(tmp_path)})

    assert config.get("sources") == {"google_play": {"retry_backoff_seconds": 1.0}}
    assert config.get("tools.obsolete_tool") is None
    assert config.get("tools.jadx") == "/opt/jadx"


def test_default_workspace_is_separate_from_legacy_workspace(tmp_path):
    config = Config(environ={"HOME": str(tmp_path)})

    assert config.get("workspace") == str(tmp_path / "APK-Workbench-Google-Play")
