"""Independent on-disk verification for completed Google Play acquisition runs."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase


class AcquisitionVerificationError(RuntimeError):
    """Raised when acquired files do not match the immutable Play run manifest."""


def _contained_regular_file(path: Path, root: Path, description: str) -> Path:
    if path.is_symlink():
        raise AcquisitionVerificationError(f"Refusing symlinked {description}: {path}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise AcquisitionVerificationError(
            f"{description} is missing or resolves outside the download workspace: {path}"
        ) from exc
    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise AcquisitionVerificationError(f"Cannot stat {description}: {path}") from exc
    if not stat.S_ISREG(mode):
        raise AcquisitionVerificationError(f"{description} is not a regular file: {path}")
    return resolved


def _hash_file(path: Path, algorithm: str) -> str:
    try:
        digest = hashlib.new(algorithm)
    except (TypeError, ValueError) as exc:
        raise AcquisitionVerificationError(
            f"Unsupported Play digest algorithm: {algorithm!r}"
        ) from exc
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    if path.is_symlink():
        raise AcquisitionVerificationError(f"Refusing symlinked verification report: {path}")
    if path.parent.is_symlink():
        raise AcquisitionVerificationError(f"Refusing symlinked report directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def verify_google_play_run(workspace: str | Path, run_id: str) -> dict[str, Any]:
    """Re-hash every APK/OBB on disk and reconcile it with the run and bundle manifests.

    The downloader already verifies Play's hashes. This second pass is deliberately
    independent: it validates the final paths, file sizes, local SHA-256 values, Play
    digests, and the immutable run CSV before Phase One is declared complete.
    """
    if not isinstance(run_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", run_id
    ):
        raise AcquisitionVerificationError("Run ID contains invalid characters.")

    root = Path(workspace).expanduser().resolve()
    downloads_root = root / "downloads"
    if downloads_root.is_symlink() or not downloads_root.is_dir():
        raise AcquisitionVerificationError(
            f"Google Play downloads directory is missing or unsafe: {downloads_root}"
        )
    downloads_root = downloads_root.resolve(strict=True)

    try:
        database = WorkspaceDatabase(root)
        rows = database.read_manifest(run_id)
    except DatabaseError as exc:
        raise AcquisitionVerificationError(
            f"Cannot read immutable acquisition manifest for run {run_id}: {exc}"
        ) from exc
    if not rows:
        raise AcquisitionVerificationError(
            f"Run {run_id} has an empty acquisition manifest; no APK files can be verified."
        )

    rows_by_bundle: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in rows:
        if row.get("source") != "google_play":
            raise AcquisitionVerificationError(
                f"Run {run_id} contains a non-Google-Play manifest item."
            )
        package_id = row.get("package_id", "")
        version_code = row.get("version_code", "")
        local_path_value = row.get("local_path", "")
        if not package_id or not version_code or not local_path_value:
            raise AcquisitionVerificationError(
                f"Run {run_id} contains a manifest row with missing artifact identity or path."
            )
        candidate = Path(local_path_value).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        file_path = _contained_regular_file(
            candidate, downloads_root, "manifest APK component"
        )
        size = file_path.stat().st_size
        expected_size = int(row.get("size") or -1)
        if size != expected_size:
            raise AcquisitionVerificationError(
                f"Size mismatch for {file_path.name}: expected {expected_size}, got {size}."
            )
        actual_sha256 = _hash_file(file_path, "sha256")
        expected_sha256 = (row.get("sha256") or "").lower()
        if actual_sha256 != expected_sha256:
            raise AcquisitionVerificationError(
                f"SHA-256 mismatch for {file_path}: expected {expected_sha256}, got {actual_sha256}."
            )
        rows_by_bundle.setdefault((package_id, version_code), []).append(
            {**row, "_resolved_path": str(file_path), "_sha256": actual_sha256}
        )

    bundles: list[dict[str, Any]] = []
    total_apks = 0
    total_obbs = 0
    total_bytes = 0

    for (package_id, version_code), manifest_rows in sorted(rows_by_bundle.items()):
        bundle_dirs = {Path(row["_resolved_path"]).parent for row in manifest_rows}
        if len(bundle_dirs) != 1:
            raise AcquisitionVerificationError(
                f"Manifest rows for {package_id} v{version_code} span multiple bundle directories."
            )
        bundle_dir = next(iter(bundle_dirs))
        if bundle_dir.is_symlink():
            raise AcquisitionVerificationError(f"Refusing symlinked bundle directory: {bundle_dir}")
        try:
            resolved_dir = bundle_dir.resolve(strict=True)
            resolved_dir.relative_to(downloads_root)
        except (OSError, ValueError) as exc:
            raise AcquisitionVerificationError(
                f"Bundle directory escapes the downloads workspace: {bundle_dir}"
            ) from exc

        bundle_manifest = bundle_dir / "google-play-bundle.json"
        bundle_manifest = _contained_regular_file(
            bundle_manifest, downloads_root, "Google Play bundle manifest"
        )
        try:
            metadata = json.loads(bundle_manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AcquisitionVerificationError(
                f"Cannot read Google Play bundle manifest: {bundle_manifest}"
            ) from exc
        if not isinstance(metadata, dict):
            raise AcquisitionVerificationError(
                f"Google Play bundle manifest is not a JSON object: {bundle_manifest}"
            )
        if (
            metadata.get("source") != "google_play"
            or metadata.get("run_id") != run_id
            or metadata.get("package_id") != package_id
            or str(metadata.get("version_code")) != version_code
        ):
            raise AcquisitionVerificationError(
                f"Bundle identity does not match the immutable run manifest: {bundle_manifest}"
            )

        component_rows = metadata.get("files")
        if not isinstance(component_rows, list) or not component_rows:
            raise AcquisitionVerificationError(
                f"Bundle manifest contains no components: {bundle_manifest}"
            )

        names: set[str] = set()
        apk_hashes: set[str] = set()
        bundle_name_hashes: set[tuple[str, str]] = set()
        apk_count = 0
        obb_count = 0
        package_bytes = 0
        has_base_apk = False
        for component in component_rows:
            if not isinstance(component, dict):
                raise AcquisitionVerificationError(
                    f"Malformed component entry in {bundle_manifest}."
                )
            name = component.get("name")
            if (
                not isinstance(name, str)
                or name in {"", ".", ".."}
                or Path(name).name != name
                or not name.endswith((".apk", ".obb"))
                or name in names
            ):
                raise AcquisitionVerificationError(
                    f"Unsafe or duplicate component name in {bundle_manifest}: {name!r}"
                )
            names.add(name)
            kind = component.get("kind")
            if kind not in {"apk", "obb"}:
                raise AcquisitionVerificationError(
                    f"Unsupported component kind for {name}: {kind!r}"
                )
            if (kind == "apk") != name.endswith(".apk"):
                raise AcquisitionVerificationError(
                    f"Component kind does not match filename for {name}."
                )
            if component.get("play_hash_verified") is not True:
                raise AcquisitionVerificationError(
                    f"Play digest was not marked verified for {name}."
                )

            component_path = _contained_regular_file(
                bundle_dir / name, downloads_root, f"bundle component {name}"
            )
            try:
                expected_size = int(component.get("size"))
            except (TypeError, ValueError) as exc:
                raise AcquisitionVerificationError(
                    f"Invalid expected size for component {name}."
                ) from exc
            actual_size = component_path.stat().st_size
            if actual_size != expected_size:
                raise AcquisitionVerificationError(
                    f"Size mismatch for {component_path}: expected {expected_size}, got {actual_size}."
                )

            expected_sha256 = str(component.get("sha256") or "").lower()
            actual_sha256 = _hash_file(component_path, "sha256")
            if actual_sha256 != expected_sha256:
                raise AcquisitionVerificationError(
                    f"Local SHA-256 mismatch for {component_path}."
                )

            algorithm = str(component.get("play_hash_algorithm") or "").lower()
            if algorithm not in {"sha1", "sha256"}:
                raise AcquisitionVerificationError(
                    f"Unsupported Play digest algorithm for {name}: {algorithm!r}"
                )
            expected_play_hash = str(component.get("play_hash") or "").lower()
            actual_play_hash = _hash_file(component_path, algorithm)
            if actual_play_hash != expected_play_hash:
                raise AcquisitionVerificationError(
                    f"Play-provided {algorithm} mismatch for {component_path}."
                )

            bundle_name_hashes.add((name, actual_sha256))
            package_bytes += actual_size
            if kind == "apk":
                apk_count += 1
                apk_hashes.add(actual_sha256)
                has_base_apk = has_base_apk or name == "base.apk"
            else:
                obb_count += 1

        if not has_base_apk:
            raise AcquisitionVerificationError(
                f"Bundle does not contain base.apk: {bundle_manifest}"
            )
        partials = list(bundle_dir.glob("*.part"))
        if partials:
            raise AcquisitionVerificationError(
                f"Unfinished partial download remains in {bundle_dir}: {partials[0].name}"
            )

        manifest_hashes = {item["_sha256"] for item in manifest_rows}
        manifest_name_hashes = {
            (Path(item["_resolved_path"]).name, item["_sha256"])
            for item in manifest_rows
        }
        if not manifest_name_hashes.issubset(bundle_name_hashes):
            raise AcquisitionVerificationError(
                f"A CSV-referenced APK filename is absent from bundle metadata for "
                f"{package_id} v{version_code}."
            )
        if apk_hashes != manifest_hashes:
            missing = sorted(apk_hashes - manifest_hashes)
            unexpected = sorted(manifest_hashes - apk_hashes)
            raise AcquisitionVerificationError(
                f"Bundle/CSV APK hash sets differ for {package_id} v{version_code}; "
                f"missing={missing}, unexpected={unexpected}."
            )

        total_apks += apk_count
        total_obbs += obb_count
        total_bytes += package_bytes
        bundles.append(
            {
                "package_id": package_id,
                "version_code": int(version_code),
                "directory": str(resolved_dir),
                "bundle_manifest": str(bundle_manifest),
                "apk_components": apk_count,
                "obb_components": obb_count,
                "total_bytes": package_bytes,
                "sha256": sorted(apk_hashes),
            }
        )

    summary: dict[str, Any] = {
        "source": "google_play",
        "run_id": run_id,
        "status": "verified",
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest_path": str(root / "database" / "run_manifests" / f"run_{run_id}.csv"),
        "manifest_apk_records": len(rows),
        "verified_bundles": len(bundles),
        "apk_components": total_apks,
        "obb_components": total_obbs,
        "total_bytes": total_bytes,
        "bundles": bundles,
    }
    report_path = root / "reports" / f"phase_one_verification_{run_id}.json"
    _write_report(report_path, summary)
    summary["report_path"] = str(report_path)
    return summary
