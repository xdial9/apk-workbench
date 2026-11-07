from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest

from apkworkbench.sources import google_play as gp


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class FakePlayFile:
    def __init__(self, name: str, payload: bytes, algorithm: str = "sha256"):
        self.name = name
        self.size = len(payload)
        self.url = "https://play.example.invalid/file"
        digest = hashlib.new(algorithm, payload).digest()
        self.sha256 = _b64(digest) if algorithm == "sha256" else ""
        self.sha1 = _b64(digest) if algorithm == "sha1" else ""

    def expected_digest(self):
        return ("sha256", self.sha256) if self.sha256 else ("sha1", self.sha1)


def _doc(package="com.example.app"):
    return SimpleNamespace(
        docid=package,
        title="Example App",
        creator="Example Developer",
        details=SimpleNamespace(
            appDetails=SimpleNamespace(
                versionString="2.4.1",
                versionCode=241,
                certificateSet=[],
            )
        ),
    )


def test_base64url_hash_is_decoded_to_hex():
    raw = hashlib.sha256(b"play hash").digest()
    assert gp._hex_from_b64url(_b64(raw)) == raw.hex()


def test_invalid_package_id_is_rejected_before_api_call():
    source = gp.GooglePlaySource()
    with pytest.raises(ValueError, match="Invalid Android package ID"):
        source.inspect("../not-an-app")


def test_inspect_captures_play_delivery_hashes(monkeypatch):
    base = FakePlayFile("base.apk", b"base bytes")
    split = FakePlayFile("split_config.en.apk", b"split bytes")
    monkeypatch.setattr(gp.play_download, "play_files", lambda _package, _delivery: [base, split])
    source = gp.GooglePlaySource()
    source._call = lambda operation: operation(
        SimpleNamespace(app_delivery=lambda _package, _version=None: (_doc(), object()))
    )

    plan = source.inspect("com.example.app")

    assert plan.app.package_id == "com.example.app"
    assert plan.app.version_code == 241
    assert [item.name for item in plan.files] == ["base.apk", "split_config.en.apk"]
    assert all(item.expected_algorithm == "sha256" for item in plan.files)
    assert all(len(item.sha256) == 64 for item in plan.files)


def test_download_preserves_and_verifies_base_split_and_obb(monkeypatch, tmp_path):
    payloads = {
        "base.apk": b"base apk",
        "split_config.en.apk": b"language split",
        "main.241.com.example.app.obb": b"expansion data",
    }
    play_files = [
        FakePlayFile("base.apk", payloads["base.apk"]),
        FakePlayFile("split_config.en.apk", payloads["split_config.en.apk"]),
        FakePlayFile("main.241.com.example.app.obb", payloads["main.241.com.example.app.obb"], "sha1"),
    ]
    monkeypatch.setattr(gp.play_download, "play_files", lambda _package, _delivery: play_files)

    class FakeDownloader:
        def __init__(self, _delivery):
            pass

        def fetch(self, item, directory):
            (directory / item.name).write_bytes(payloads[item.name])
            return True

    monkeypatch.setattr(gp.play_download, "Downloader", FakeDownloader)
    plan = gp.PlayBundlePlan(
        app=gp.PlayApp("com.example.app", "Example App", "Example Developer", "2.4.1", 241),
        files=tuple(
            gp.PlayFile(
                name=item.name,
                size=item.size,
                sha256=hashlib.sha256(payloads[item.name]).hexdigest() if item.sha256 else "",
                expected_algorithm=item.expected_digest()[0],
                expected_digest=hashlib.new(
                    item.expected_digest()[0], payloads[item.name]
                ).hexdigest(),
                kind="apk" if item.name.endswith(".apk") else "obb",
            )
            for item in play_files
        ),
        signer_sha256=("a" * 64,),
        _doc=_doc(),
        _delivery=object(),
    )

    result = gp.GooglePlaySource().download(plan, workspace=tmp_path, run_id="test-run")

    assert {path.name for path in result.apk_files} == {"base.apk", "split_config.en.apk"}
    assert {path.name for path in result.obb_files} == {"main.241.com.example.app.obb"}
    assert result.manifest_path.is_file()
    assert len(result.manifest_sha256) == 64
    assert (result.directory / "google-play-bundle.json").is_file()
