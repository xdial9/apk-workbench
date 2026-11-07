"""CLI integration tests for authenticated F-Droid discovery."""
from __future__ import annotations

import importlib
import logging
from types import SimpleNamespace

from click.testing import CliRunner


cli = importlib.import_module("apkworkbench.cli.main")


class StubConfig:
    def get(self, key, default=None):
        if key == "sources.fdroid":
            return {
                "repository_url": "https://f-droid.org/repo",
                "key_url": "https://keys.example.invalid/fdroid.asc",
                "signer_fingerprint": "37D2C98789D8311948394E3E41E7044E1DBA2E89",
                "timeout_seconds": 12,
                "max_index_bytes": 1000,
                "max_signature_bytes": 100,
                "max_key_bytes": 200,
            }
        return default


class StubRepositoryClient:
    def __init__(self, verifier, **kwargs):
        self.signer_fingerprint = kwargs["signer_fingerprint"]
        self.kwargs = kwargs

    def fetch_verified_index(self):
        return b"authenticated-index-bytes"


class StubParser:
    def __init__(self, repository_url):
        self.repository_url = repository_url

    def parse(self, index_data):
        assert index_data == b"authenticated-index-bytes"
        return [
            SimpleNamespace(
                package_id="org.example.alpha",
                version_code=7,
                version_name="7.0",
                size=1024,
                sha256="a" * 64,
            ),
            SimpleNamespace(
                package_id="org.example.alpha",
                version_code=6,
                version_name="6.0",
                size=900,
                sha256="b" * 64,
            ),
            SimpleNamespace(
                package_id="org.example.beta",
                version_code=3,
                version_name="3.0",
                size=2048,
                sha256="c" * 64,
            ),
        ]


def install_discovery_stubs(monkeypatch):
    monkeypatch.setattr(cli, "Config", StubConfig)
    monkeypatch.setattr(cli, "setup_logging", lambda config: logging.getLogger("test-apkworkbench"))
    monkeypatch.setattr(cli, "GpgVerifier", lambda config: object())
    monkeypatch.setattr(cli, "FdroidRepositoryClient", StubRepositoryClient)
    monkeypatch.setattr(cli, "FdroidIndexParser", StubParser)


def test_discover_authenticates_index_and_displays_latest_per_package(monkeypatch):
    install_discovery_stubs(monkeypatch)

    result = CliRunner().invoke(cli.main, ["discover", "--limit", "10"])

    assert result.exit_code == 0, result.output
    assert "Index signature: VERIFIED" in result.output
    assert "Indexed APK version records: 3" in result.output
    assert "Distinct binary SHA-256 values: 3" in result.output
    assert "org.example.alpha | 7.0 | code 7" in result.output
    assert "org.example.beta | 3.0 | code 3" in result.output
    assert "org.example.alpha | 6.0 | code 6" not in result.output


def test_discover_supports_exact_package_filter_and_zero_display_limit(monkeypatch):
    install_discovery_stubs(monkeypatch)

    result = CliRunner().invoke(
        cli.main,
        ["discover", "--package", "org.example.beta", "--limit", "0"],
    )

    assert result.exit_code == 0, result.output
    assert "Exact package filter: org.example.beta" in result.output
    assert "LATEST INDEXED VERSIONS" in result.output
    assert "org.example.beta | 3.0" not in result.output
    assert "1 additional package records not displayed." in result.output


def test_discover_stops_when_index_authentication_fails(monkeypatch):
    install_discovery_stubs(monkeypatch)

    class RejectingClient(StubRepositoryClient):
        def fetch_verified_index(self):
            from apkworkbench.sources.fdroid_repository import FdroidRepositoryError

            raise FdroidRepositoryError("invalid detached signature")

    monkeypatch.setattr(cli, "FdroidRepositoryClient", RejectingClient)
    result = CliRunner().invoke(cli.main, ["discover"])

    assert result.exit_code == 1
    assert "Discovery failed: invalid detached signature" in result.output
