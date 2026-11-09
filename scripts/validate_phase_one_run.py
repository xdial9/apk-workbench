#!/usr/bin/env python3
"""Validate a Phase One Google Play acquisition workspace without running analysis tools."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


class PhaseOneValidationError(ValueError):
    """Raised when the on-disk Google Play acquisition is incomplete or inconsistent."""


def _hash_file(path: Path, algorithm: str = "sha256") -> tuple[int, str]:
    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise PhaseOneValidationError(f"Unsupported digest algorithm: {algorithm}") from exc
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _read_csv(path: Path, label: str) -> list[dict[str, str]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise PhaseOneValidationError(f"{label} is missing or empty: {path}")
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise PhaseOneValidationError(f"{label} contains no records: {path}")
    return rows


def validate_workspace(
    workspace: str | Path,
    *,
    expected_package_id: str | None = None,
) -> dict[str, Any]:
    root = Path(workspace).expanduser().resolve()
    if not root.is_dir():
        raise PhaseOneValidationError(f"Workspace directory does not exist: {root}")

    downloads = root / "downloads"
    database = root / "database"
    if downloads.is_symlink() or not downloads.is_dir():
        raise PhaseOneValidationError(f"Downloads directory is missing or unsafe: {downloads}")
    if database.is_symlink() or not database.is_dir():
        raise PhaseOneValidationError(f"Database directory is missing or unsafe: {database}")

    discovery_path = database / "google_play_discovery.csv"
    discovered = _read_csv(discovery_path, "Google Play discovery catalogue")
    discovered_ids = {row.get("package_id", "") for row in discovered}
    if expected_package_id and expected_package_id not in discovered_ids:
        raise PhaseOneValidationError(
            f"Target package was not recorded by discovery: {expected_package_id}"
        )

    bundle_paths = sorted(
        downloads.glob("*/google-play-bundle.json"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    if expected_package_id:
        matching_bundles = []
        for path in bundle_paths:
            try:
                bundle = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if bundle.get("package_id") == expected_package_id:
                matching_bundles.append(path)
        bundle_paths = matching_bundles
    if len(bundle_paths) != 1:
        raise PhaseOneValidationError(
            f"Expected one matching Google Play bundle manifest, found {len(bundle_paths)}"
        )

    bundle_path = bundle_paths[0]
    if bundle_path.is_symlink() or not bundle_path.is_file():
        raise PhaseOneValidationError(f"Bundle manifest is missing or unsafe: {bundle_path}")
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PhaseOneValidationError(f"Bundle manifest is invalid JSON: {bundle_path}") from exc

    run_id = str(bundle.get("run_id") or "")
    package_id = str(bundle.get("package_id") or "")
    if bundle.get("source") != "google_play" or not run_id or not package_id:
        raise PhaseOneValidationError("Bundle manifest lacks a valid source, run ID, or package ID")
    if expected_package_id and package_id != expected_package_id:
        raise PhaseOneValidationError(
            f"Downloaded package {package_id} does not match requested package {expected_package_id}"
        )

    run_manifest = database / "run_manifests" / f"run_{run_id}.csv"
    manifest_rows = _read_csv(run_manifest, "Frozen run manifest")
    for row in manifest_rows:
        if row.get("source") != "google_play":
            raise PhaseOneValidationError("Frozen run manifest contains a non-Google-Play source")
        if row.get("run_id") != run_id or row.get("package_id") != package_id:
            raise PhaseOneValidationError("Frozen run manifest identity does not match the bundle")

    bundle_directory = bundle_path.parent.resolve()
    verified_files: list[dict[str, Any]] = []
    files_by_name: dict[str, dict[str, Any]] = {}
    apk_names: set[str] = set()

    for item in bundle.get("files") or []:
        name = item.get("name")
        if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."}:
            raise PhaseOneValidationError(f"Unsafe component filename in bundle manifest: {name!r}")
        if name in files_by_name:
            raise PhaseOneValidationError(f"Duplicate component in bundle manifest: {name}")

        path = bundle_directory / name
        if path.is_symlink() or not path.is_file():
            raise PhaseOneValidationError(f"Downloaded component is missing or unsafe: {path}")
        size, local_sha256 = _hash_file(path, "sha256")
        expected_size = int(item.get("size") or 0)
        if size <= 0 or size != expected_size:
            raise PhaseOneValidationError(f"Component size mismatch: {name}")
        if local_sha256 != item.get("sha256"):
            raise PhaseOneValidationError(f"Local SHA-256 mismatch: {name}")
        if item.get("play_hash_verified") is not True:
            raise PhaseOneValidationError(f"Play-provided digest was not verified: {name}")

        play_algorithm = str(item.get("play_hash_algorithm") or "")
        play_hash = str(item.get("play_hash") or "")
        if not play_algorithm or not play_hash:
            raise PhaseOneValidationError(f"Play digest metadata is missing: {name}")
        _, actual_play_hash = _hash_file(path, play_algorithm)
        if actual_play_hash.lower() != play_hash.lower():
            raise PhaseOneValidationError(f"Play-provided hash mismatch: {name}")

        verified = {
            "name": name,
            "kind": item.get("kind"),
            "size": size,
            "sha256": local_sha256,
            "play_hash_algorithm": play_algorithm,
            "play_hash": play_hash,
            "play_hash_verified": True,
            "path": str(path.relative_to(root)),
        }
        verified_files.append(verified)
        files_by_name[name] = verified
        if item.get("kind") == "apk":
            apk_names.add(name)

    if not verified_files or "base.apk" not in apk_names:
        raise PhaseOneValidationError("No complete base.apk was acquired")
    if any(path.is_symlink() for path in downloads.rglob("*")):
        raise PhaseOneValidationError("A symlink exists inside the downloads tree")

    manifest_names: set[str] = set()
    for row in manifest_rows:
        local_path_value = row.get("local_path") or ""
        if not local_path_value:
            raise PhaseOneValidationError("A frozen manifest row has no local_path")
        local_path = Path(local_path_value).expanduser()
        if not local_path.is_absolute():
            local_path = root / local_path
        resolved = local_path.resolve()
        try:
            resolved.relative_to(bundle_directory)
        except ValueError as exc:
            raise PhaseOneValidationError(
                f"Frozen manifest path escapes the acquired bundle directory: {local_path}"
            ) from exc
        name = resolved.name
        manifest_names.add(name)
        verified = files_by_name.get(name)
        if not verified or row.get("sha256") != verified["sha256"]:
            raise PhaseOneValidationError(f"Frozen manifest hash/path does not match: {name}")

    if not manifest_names or not manifest_names.issubset(apk_names):
        raise PhaseOneValidationError("Frozen run manifest does not reference acquired APK components")
    partials = [
        path for path in downloads.rglob("*.part")
        if ".quarantine" not in path.parts
    ]
    if partials:
        raise PhaseOneValidationError(
            "Unreconciled partial download files remain: " + ", ".join(str(path) for path in partials)
        )

    result: dict[str, Any] = {
        "phase": 1,
        "status": "verified",
        "source": "google_play",
        "run_id": run_id,
        "package_id": package_id,
        "version_code": bundle.get("version_code"),
        "version_name": bundle.get("version_name"),
        "discovered_candidates": len(discovered),
        "verified_apk_count": len(apk_names),
        "verified_component_count": len(verified_files),
        "bundle_directory": str(bundle_directory),
        "bundle_manifest": str(bundle_path),
        "run_manifest": str(run_manifest),
        "run_manifest_sha256": _hash_file(run_manifest)[1],
        "quarantined_files": bundle.get("quarantined_files") or [],
        "files": verified_files,
    }
    output_path = root / "phase-one-result.json"
    fd, temporary_name = tempfile.mkstemp(prefix="phase-one-result.", suffix=".tmp", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary_name, output_path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path, help="APK Workbench workspace containing downloads/ and database/")
    parser.add_argument("--package-id", help="Require this package ID in discovery and download output")
    args = parser.parse_args()
    try:
        result = validate_workspace(args.workspace, expected_package_id=args.package_id)
    except (OSError, PhaseOneValidationError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Phase One validation failed: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
