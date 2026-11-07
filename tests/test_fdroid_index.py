"""Tests for F-Droid index-v2 parsing and path validation."""
import json

import pytest

from apkworkbench.sources.fdroid import FdroidIndexError, FdroidIndexParser


APK_SHA256 = "a" * 64


def sample_index(path="/org.example.app_12.apk"):
    return {
        "packages": {
            "org.example.app": {
                "metadata": {
                    "name": {
                        "en-US": "Example App",
                        "fr-FR": "Application Exemple",
                    }
                },
                "versions": {
                    APK_SHA256: {
                        "file": {
                            "name": path,
                            "sha256": APK_SHA256,
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


def test_parse_normalizes_index_v2_sha256_key_and_root_relative_path():
    artifacts = FdroidIndexParser().parse(json.dumps(sample_index()))
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.package_id == "org.example.app"
    assert artifact.version_code == 12
    assert artifact.version_name == "1.2"
    assert artifact.app_name == "Example App"
    assert artifact.repository_path == "org.example.app_12.apk"
    assert artifact.download_url == "https://f-droid.org/repo/org.example.app_12.apk"
    assert artifact.sha256 == APK_SHA256
    assert artifact.signer_sha256 == ("b" * 64,)


@pytest.mark.parametrize(
    "path",
    [
        "../evil.apk",
        "https://evil.example/a.apk",
        "//evil.example/a.apk",
        "/a/../../evil.apk",
        "/%2e%2e/evil.apk",
        r"folder\\evil.apk",
    ],
)
def test_rejects_unsafe_artifact_paths(path):
    with pytest.raises(FdroidIndexError, match="Unsafe"):
        FdroidIndexParser().parse(json.dumps(sample_index(path)))


def test_accepts_repository_root_relative_path_with_one_leading_slash():
    artifact = FdroidIndexParser().parse(
        json.dumps(sample_index("/org.example.app_12.apk"))
    )[0]

    assert artifact.repository_path == "org.example.app_12.apk"
    assert artifact.download_url.endswith("/org.example.app_12.apk")


def test_rejects_version_map_key_that_does_not_match_apk_hash():
    data = sample_index()
    package = data["packages"]["org.example.app"]
    package["versions"]["c" * 64] = package["versions"].pop(APK_SHA256)

    with pytest.raises(FdroidIndexError, match="map key does not match"):
        FdroidIndexParser().parse(json.dumps(data))


def test_rejects_non_sha256_version_map_key():
    data = sample_index()
    package = data["packages"]["org.example.app"]
    package["versions"]["12"] = package["versions"].pop(APK_SHA256)

    with pytest.raises(FdroidIndexError, match="version map key"):
        FdroidIndexParser().parse(json.dumps(data))


def test_rejects_bad_hash():
    data = sample_index()
    data["packages"]["org.example.app"]["versions"][APK_SHA256]["file"]["sha256"] = (
        "not-a-hash"
    )
    with pytest.raises(FdroidIndexError, match="SHA-256"):
        FdroidIndexParser().parse(json.dumps(data))


def test_rejects_bad_size():
    data = sample_index()
    data["packages"]["org.example.app"]["versions"][APK_SHA256]["file"]["size"] = -1
    with pytest.raises(FdroidIndexError, match="size"):
        FdroidIndexParser().parse(json.dumps(data))


def test_rejects_boolean_version_code():
    data = sample_index()
    data["packages"]["org.example.app"]["versions"][APK_SHA256]["manifest"][
        "versionCode"
    ] = True
    with pytest.raises(FdroidIndexError, match="versionCode"):
        FdroidIndexParser().parse(json.dumps(data))


def test_requires_packages_mapping():
    with pytest.raises(FdroidIndexError, match="packages object"):
        FdroidIndexParser().parse("{}")
