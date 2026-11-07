"""Tests for F-Droid index-v2 parsing and path validation."""
import json

import pytest

from apkworkbench.sources.fdroid import FdroidIndexError, FdroidIndexParser


def sample_index(path="/org.example.app_12.apk"):
    return {
        "packages": {
            "org.example.app": {
                "metadata": {"name": "Example App"},
                "versions": {
                    "12": {
                        "file": {
                            "name": path,
                            "sha256": "a" * 64,
                            "size": 12345,
                        },
                        "manifest": {
                            "versionCode": 12,
                            "versionName": "1.2",
                            "signer": {"sha256": ["b" * 64]},
                        },
                    }
                },
            }
        }
    }


def test_parse_normalizes_index_v2_artifact():
    artifacts = FdroidIndexParser().parse(json.dumps(sample_index()))
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.package_id == "org.example.app"
    assert artifact.version_code == 12
    assert artifact.version_name == "1.2"
    assert artifact.app_name == "Example App"
    assert artifact.download_url == "https://f-droid.org/repo/org.example.app_12.apk"
    assert artifact.sha256 == "a" * 64
    assert artifact.signer_sha256 == ("b" * 64,)


@pytest.mark.parametrize("path", ["../evil.apk", "https://evil.example/a.apk", "//evil.example/a.apk", "/a/../../evil.apk"])
def test_rejects_unsafe_artifact_paths(path):
    with pytest.raises(FdroidIndexError, match="Unsafe"):
        FdroidIndexParser().parse(json.dumps(sample_index(path)))


def test_rejects_bad_hash():
    data = sample_index()
    data["packages"]["org.example.app"]["versions"]["12"]["file"]["sha256"] = "not-a-hash"
    with pytest.raises(FdroidIndexError, match="SHA-256"):
        FdroidIndexParser().parse(json.dumps(data))


def test_rejects_bad_size():
    data = sample_index()
    data["packages"]["org.example.app"]["versions"]["12"]["file"]["size"] = -1
    with pytest.raises(FdroidIndexError, match="size"):
        FdroidIndexParser().parse(json.dumps(data))


def test_requires_packages_mapping():
    with pytest.raises(FdroidIndexError, match="packages object"):
        FdroidIndexParser().parse("{}")
