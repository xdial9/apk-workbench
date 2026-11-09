import csv
import hashlib
import json
from pathlib import Path

import pytest

from scripts.validate_phase_one_run import PhaseOneValidationError, validate_workspace


PACKAGE_ID = "com.example.finance"
RUN_ID = "phase-one-test-run"


def _sha(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    database = root / "database"
    downloads = root / "downloads" / f"{PACKAGE_ID}-241"
    manifest_dir = database / "run_manifests"
    downloads.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)

    contents = {
        "base.apk": (b"base dex and resources", "apk", "sha256"),
        "split_config.en.apk": (b"english resources", "apk", "sha256"),
        "main.241.com.example.finance.obb": (b"expansion data", "obb", "sha1"),
    }
    files = []
    apk_rows = []
    for name, (data, kind, play_algorithm) in contents.items():
        path = downloads / name
        path.write_bytes(data)
        play_hash = _sha(data, play_algorithm)
        local_sha256 = _sha(data)
        files.append({
            "name": name,
            "kind": kind,
            "size": len(data),
            "sha256": local_sha256,
            "play_hash_algorithm": play_algorithm,
            "play_hash": play_hash,
            "play_hash_verified": True,
        })
        if kind == "apk":
            apk_rows.append({
                "run_id": RUN_ID,
                "source": "google_play",
                "package_id": PACKAGE_ID,
                "local_path": str(path.resolve()),
                "sha256": local_sha256,
            })

    _write_csv(
        database / "google_play_discovery.csv",
        ["package_id", "title", "developer"],
        [{"package_id": PACKAGE_ID, "title": "Example Finance", "developer": "Example"}],
    )
    _write_csv(
        manifest_dir / f"{RUN_ID}.csv",
        ["run_id", "source", "package_id", "local_path", "sha256"],
        apk_rows,
    )

    bundle = {
        "source": "google_play",
        "run_id": RUN_ID,
        "package_id": PACKAGE_ID,
        "version_code": 241,
        "version_name": "2.4.1",
        "files": files,
        "quarantined_files": [],
    }
    (downloads / "google-play-bundle.json").write_text(
        json.dumps(bundle, indent=2), encoding="utf-8"
    )
    return root


def test_validate_workspace_checks_actual_bytes_and_frozen_manifest(tmp_path):
    workspace = _workspace(tmp_path)

    result = validate_workspace(workspace, expected_package_id=PACKAGE_ID)

    assert result["status"] == "verified"
    assert result["run_id"] == RUN_ID
    assert result["package_id"] == PACKAGE_ID
    assert result["verified_apk_count"] == 2
    assert result["verified_component_count"] == 3
    assert Path(result["run_manifest"]).is_file()
    assert (workspace / "phase-one-result.json").is_file()


def test_validate_workspace_rejects_local_sha256_mismatch(tmp_path):
    workspace = _workspace(tmp_path)
    base_apk = next((workspace / "downloads").rglob("base.apk"))
    base_apk.write_bytes(b"tampered")

    with pytest.raises(PhaseOneValidationError, match="Local SHA-256 mismatch"):
        validate_workspace(workspace, expected_package_id=PACKAGE_ID)


def test_validate_workspace_recomputes_play_provided_digest(tmp_path):
    workspace = _workspace(tmp_path)
    bundle_path = next((workspace / "downloads").rglob("google-play-bundle.json"))
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["files"][0]["play_hash"] = "0" * 64
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(PhaseOneValidationError, match="Play-provided hash mismatch"):
        validate_workspace(workspace, expected_package_id=PACKAGE_ID)


def test_validate_workspace_requires_package_in_discovery_catalogue(tmp_path):
    workspace = _workspace(tmp_path)

    with pytest.raises(PhaseOneValidationError, match="not recorded by discovery"):
        validate_workspace(workspace, expected_package_id="com.other.app")


def test_validate_workspace_requires_a_frozen_manifest_for_the_run(tmp_path):
    workspace = _workspace(tmp_path)
    manifest = next((workspace / "database" / "run_manifests").glob("*.csv"))
    manifest.unlink()

    with pytest.raises(PhaseOneValidationError, match="Expected one frozen manifest"):
        validate_workspace(workspace, expected_package_id=PACKAGE_ID)
