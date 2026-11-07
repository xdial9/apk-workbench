"""Tests for deterministic unique-binary acquisition selection."""
from __future__ import annotations

import pytest

from apkworkbench.acquisition.selector import select_new_artifacts
from apkworkbench.sources.fdroid import FdroidArtifact


def artifact(package_id, version_code, digest):
    return FdroidArtifact(
        package_id=package_id,
        version_code=version_code,
        version_name=str(version_code),
        app_name=package_id,
        repository_path=f"{package_id}-{version_code}.apk",
        download_url=f"https://f-droid.org/repo/{package_id}-{version_code}.apk",
        sha256=digest * 64,
        size=100,
        signer_sha256=(),
        metadata={},
    )


def test_selects_latest_version_across_packages_before_older_versions():
    items = [
        artifact("org.alpha", 2, "a"),
        artifact("org.alpha", 1, "b"),
        artifact("org.beta", 1, "c"),
    ]

    result = select_new_artifacts(items, set(), 3)

    assert [(item.package_id, item.version_code) for item in result.artifacts] == [
        ("org.alpha", 2),
        ("org.beta", 1),
        ("org.alpha", 1),
    ]
    assert result.shortfall == 0


def test_excludes_history_and_duplicate_hashes_within_same_selection():
    items = [
        artifact("org.alpha", 2, "a"),
        artifact("org.beta", 1, "a"),
        artifact("org.gamma", 1, "b"),
    ]

    result = select_new_artifacts(items, {"b" * 64}, 5)

    assert [item.package_id for item in result.artifacts] == ["org.alpha"]
    assert result.shortfall == 4


def test_package_filter_is_exact():
    items = [artifact("org.alpha", 1, "a"), artifact("org.alphabet", 1, "b")]

    result = select_new_artifacts(items, set(), 5, package_filter="org.alpha")

    assert [item.package_id for item in result.artifacts] == ["org.alpha"]
    assert result.shortfall == 4


def test_count_must_be_positive():
    with pytest.raises(ValueError, match="at least 1"):
        select_new_artifacts([], set(), 0)
