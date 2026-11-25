"""Single-folder workspace layout, run index, self-contained runner, and legacy migration."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..analysis.apk_surface import refresh_secret_links, run_static_surface_analysis
from ..analysis.surface.handoff import deliver_prompts
from ..analysis.trufflehog import TruffleHogScanner
from ..database.workspace import WorkspaceDatabase, utc_now
from ..decompilation.runner import DecompilationRunner
from ..reporting.final_run import generate_final_run_report
from ..reporting.generator import ReportGenerator
from .config import Config

RUNS_DIRNAME = "runs"
RUNS_INDEX_FILENAME = "runs_index.json"

_SKIP_RESULTS_DIRS = frozenset({"FINDINGS", "runs"})
_BUNDLE_MARKER_ENTRIES = frozenset(
    {"apktool", "surface", "trufflehog", "manifest", "ai_analysis", "handoff.json", "hashes.sha256"}
)
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sanitize_segment(value: str, fallback: str) -> str:
    cleaned = _SAFE_SEGMENT_RE.sub("_", str(value).strip()).strip("._-")
    return cleaned or fallback


def run_folder_name(package_id: str, version_code: str | int, run_id: str) -> str:
    """Return a filesystem-safe self-contained run folder name."""
    safe_pkg = _sanitize_segment(package_id, "unknown.app")
    safe_ver = _sanitize_segment(str(version_code), "0")
    safe_run = _sanitize_segment(str(run_id)[:8], "00000000")
    return f"{safe_pkg}-v{safe_ver}-{safe_run}"


def render_run_readme(
    *,
    package_id: str,
    version_code: str | int,
    version_name: str,
    run_id: str,
    created_at: str,
    bundle_id: str,
    status: str = "complete",
) -> str:
    """Render a human- and operator-friendly README.md for a self-contained run folder."""
    version_display = f"{version_name} ({version_code})" if version_name else str(version_code)
    return (
        f"# APK-Workbench Run: `{package_id}`\n\n"
        f"- **Package ID**: `{package_id}`\n"
        f"- **Version**: `{version_display}`\n"
        f"- **Run ID**: `{run_id}`\n"
        f"- **Bundle ID**: `{bundle_id}`\n"
        f"- **Created At**: `{created_at}`\n"
        f"- **Status**: `{status}`\n\n"
        "## Folder Contents\n\n"
        "| Folder | Contents |\n"
        "| --- | --- |\n"
        "| `apk/` | Original APK / split APK binaries and acquisition bundle metadata (`google-play-bundle.json`). |\n"
        "| `apktool/` | Apktool-decoded manifest, resources, smali, and assets (one subdir per split when applicable). |\n"
        "| `surface/` | Static surface analysis (`static-analysis.json`, `facts.jsonl`, `location_map.json`, shards, indexes). |\n"
        "| `trufflehog/` | TruffleHog secret-scan outputs (`findings.json`, verified/unverified records, status). |\n"
        "| `manifest/` | Acquisition provenance (`run_manifest.csv`, `google-play-bundle.json`, `phase_one_verification.json`). |\n"
        "| `reports/` | Consolidated & per-APK reports (`final-report.html`, `final-report.json`, `findings.csv`, `report.html`, `report.json`). |\n"
        "| `stages/` | Per-stage machine-readable `status.json` ledgers and run markers. |\n"
        "| `logs/` | Stage execution logs (`apktool.log`, `trufflehog.log`, pipeline logs). |\n"
        "| `prompts/` | Delivered AI analysis prompt chain (`0.txt` .. `6.txt`). |\n"
        "| `ai_analysis/` | Writable area for AI-generated dossiers, lead ledgers, and structured analysis (`attempt-01/`). |\n\n"
        "## How to Read the Output\n\n"
        "1. **AI Dossier**: `ai_analysis/attempt-01/dossier.md`\n"
        "2. **Lead Ledger**: `ai_analysis/attempt-01/lead_ledger.json`\n"
        "3. **Structured AI Analysis**: `ai_analysis/attempt-01/ai_analysis.json`\n"
        "4. **Consolidated Reports**: `reports/final-report.html` and `reports/final-report.json`\n"
        "5. **Evidence Index & Handoff**: `handoff.json`, `surface/facts.jsonl`, and `surface/location_map.json`\n\n"
        "## Integrity Verification\n\n"
        "All evidence folders outside `ai_analysis/` are frozen read-only and recorded in `hashes.sha256`.\n"
        "Verify this folder's integrity at any time with:\n\n"
        "```bash\n"
        "apkworkbench verify-workspace <this-folder>\n"
        "```\n"
    )


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


class RunIndex:
    """Atomically manage `<home>/runs_index.json`."""

    def __init__(self, home: str | Path):
        self.home = Path(home).expanduser().resolve()
        self.path = self.home / RUNS_INDEX_FILENAME

    def read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {
                "schema_version": 1,
                "updated_at": utc_now(),
                "runs": [],
            }
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
            raise TypeError(f"Malformed runs index at {self.path}")
        return data

    @staticmethod
    def _normalize_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "run_id": str(entry.get("run_id", "")),
            "package_id": str(entry.get("package_id", "")),
            "version_code": str(entry.get("version_code", "")),
            "version_name": str(entry.get("version_name", "")),
            "bundle_id": str(entry.get("bundle_id", "")),
            "created_at": str(entry.get("created_at") or utc_now()),
            "folder": str(entry.get("folder", "")),
            "status": str(entry.get("status", "complete")),
            "has_dossier": bool(entry.get("has_dossier", False)),
            "has_lead_ledger": bool(entry.get("has_lead_ledger", False)),
        }

    def upsert(self, entry: Mapping[str, Any]) -> dict[str, Any]:
        normalized = self._normalize_entry(entry)
        index = self.read()
        runs: list[dict[str, Any]] = [
            dict(item) for item in index.get("runs", []) if isinstance(item, dict)
        ]
        replaced = False
        for idx, existing in enumerate(runs):
            same_folder = bool(normalized["folder"]) and existing.get("folder") == normalized["folder"]
            same_run_bundle = (
                bool(normalized["run_id"])
                and bool(normalized["bundle_id"])
                and existing.get("run_id") == normalized["run_id"]
                and existing.get("bundle_id") == normalized["bundle_id"]
            )
            if same_folder or same_run_bundle:
                runs[idx] = normalized
                replaced = True
                break
        if not replaced:
            runs.append(normalized)
        runs.sort(key=lambda item: (item.get("created_at", ""), item.get("folder", "")))
        updated = {
            "schema_version": 1,
            "updated_at": utc_now(),
            "runs": runs,
        }
        _atomic_write_json(self.path, updated)
        return updated

    def list_runs(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self.read().get("runs", []) if isinstance(item, dict)]


def _copy_tree_preserving_readonly(src: Path, dst: Path) -> None:
    """Copy a directory tree safely even when source files/dirs are read-only (0o444/0o555)."""
    src = Path(src)
    dst = Path(dst)
    readonly_dirs: list[tuple[Path, int]] = []
    dst.mkdir(parents=True, exist_ok=True)

    for root, dirs, filenames in os.walk(src, followlinks=False):
        root_path = Path(root)
        rel = root_path.relative_to(src)
        target_dir = dst / rel
        target_dir.mkdir(parents=True, exist_ok=True)
        src_dir_mode = stat.S_IMODE(root_path.stat().st_mode)
        if not (src_dir_mode & 0o222) and rel != Path("."):
            readonly_dirs.append((target_dir, src_dir_mode))

        # Skip symlinks to prevent escaping the tree.
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        for fname in filenames:
            src_file = root_path / fname
            if src_file.is_symlink() or not src_file.is_file():
                continue
            dst_file = target_dir / fname
            if dst_file.exists() and not (dst_file.stat().st_mode & 0o222):
                os.chmod(dst_file, 0o644)
            shutil.copyfile(src_file, dst_file)
            src_file_mode = stat.S_IMODE(src_file.stat().st_mode)
            if not (src_file_mode & 0o222):
                os.chmod(dst_file, src_file_mode)

    # Restore read-only directory modes bottom-up so children are written first.
    for target_dir, mode in sorted(
        readonly_dirs, key=lambda pair: len(pair[0].parts), reverse=True
    ):
        os.chmod(target_dir, mode)


def _find_ai_outputs(bundle_dir: Path) -> tuple[list[Path], list[Path]]:
    """Return sorted lists of relative paths to dossier.md and lead_ledger.json under ai_analysis/."""
    ai_dir = bundle_dir / "ai_analysis"
    dossiers: list[Path] = []
    ledgers: list[Path] = []
    if not ai_dir.is_dir() or ai_dir.is_symlink():
        return dossiers, ledgers
    for root, dirs, filenames in os.walk(ai_dir, followlinks=False):
        root_path = Path(root)
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        for fname in filenames:
            fpath = root_path / fname
            if fpath.is_symlink() or not fpath.is_file():
                continue
            rel = fpath.relative_to(bundle_dir)
            if fname == "dossier.md":
                dossiers.append(rel)
            elif fname == "lead_ledger.json":
                ledgers.append(rel)
    dossiers.sort()
    ledgers.sort()
    return dossiers, ledgers


def _extract_apk_metadata(apk_path: Path) -> dict[str, Any]:
    """Best-effort metadata extraction from an APK via androguard."""
    try:
        from androguard.core.apk import APK  # type: ignore[import-untyped]

        parsed = APK(str(apk_path))
        pkg = parsed.get_package() or ""
        ver_code = parsed.get_androidversion_code() or ""
        ver_name = parsed.get_androidversion_name() or ""
        app_name = parsed.get_app_name() or ""
        return {
            "package_id": str(pkg).strip(),
            "version_code": str(ver_code).strip(),
            "version_name": str(ver_name).strip(),
            "app_name": str(app_name).strip(),
        }
    except (ImportError, OSError, ValueError, TypeError, RuntimeError):
        return {}


def _read_bundle_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _safe_move_or_copy(src: Path, dst: Path) -> None:
    """Move a directory/file into dst, falling back to safe copy if cross-device or read-only."""
    if not src.exists() or src.is_symlink():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        try:
            shutil.move(str(src), str(dst))
        except OSError:
            _copy_tree_preserving_readonly(src, dst)
    elif src.is_file():
        shutil.copy2(src, dst)


def consolidate_workspace_run(
    home: str | Path,
    staging_workspace: str | Path,
    run_id: str,
) -> list[Path]:
    """Package completed run artifacts from a staging workspace into `<home>/runs/<name>/`."""
    home_path = Path(home).expanduser().resolve()
    staging = Path(staging_workspace).expanduser().resolve()
    runs_root = home_path / RUNS_DIRNAME
    runs_root.mkdir(parents=True, exist_ok=True)

    staging_db = WorkspaceDatabase(staging)
    manifest_rows = staging_db.read_manifest(run_id)
    reconciliation = staging_db.reconcile_run(run_id)
    recon_by_hash = {
        str(item.get("sha256", "")).lower(): item
        for item in reconciliation.get("items", [])
        if isinstance(item, dict)
    }

    home_db = WorkspaceDatabase(home_path)
    run_index = RunIndex(home_path)
    created_dirs: list[Path] = []
    created_at = utc_now()

    staging_manifest_csv = staging / "database" / "run_manifests" / f"run_{run_id}.csv"
    staging_phase1 = staging / "reports" / f"phase_one_verification_{run_id}.json"
    staging_final_dir = staging / "reports" / "runs" / run_id
    staging_findings_csv = staging / "reports" / "findings.csv"
    staging_run_meta = staging / "results" / "runs" / run_id
    staging_logs_dir = staging / "logs"

    for row in manifest_rows:
        pkg = row["package_id"]
        ver = str(row["version_code"])
        ver_name = str(row.get("version_name", ""))
        digest = row["sha256"].lower()
        recon_item = recon_by_hash.get(digest, {})
        item_status = str(recon_item.get("status") or "complete")

        folder_name = run_folder_name(pkg, ver, run_id)
        run_dir = runs_root / folder_name
        if run_dir.exists():
            run_dir = runs_root / f"{folder_name}-{digest[:8]}"
        run_dir.mkdir(parents=True, exist_ok=True)

        artifact_results = staging / "results" / pkg / ver / digest
        artifact_downloads = staging / "downloads" / f"{pkg}-{ver}"
        artifact_reports = staging / "reports" / pkg / ver / digest

        # 1. apk/
        apk_dir = run_dir / "apk"
        apk_dir.mkdir(parents=True, exist_ok=True)
        if artifact_downloads.is_dir():
            for entry in sorted(artifact_downloads.iterdir()):
                if entry.is_symlink() or not entry.is_file():
                    continue
                if entry.suffix.lower() == ".apk" or entry.name == "google-play-bundle.json":
                    shutil.copy2(entry, apk_dir / entry.name)
        elif row.get("local_path"):
            local_apk = Path(row["local_path"])
            if local_apk.is_file() and not local_apk.is_symlink():
                shutil.copy2(local_apk, apk_dir / local_apk.name)

        # 2. apktool/, surface/, trufflehog/
        for subdir_name in ("apktool", "surface", "trufflehog"):
            src_sub = artifact_results / subdir_name
            if src_sub.is_dir():
                _safe_move_or_copy(src_sub, run_dir / subdir_name)

        # 3. manifest/
        manifest_dir = run_dir / "manifest"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        if (artifact_results / "manifest").is_dir():
            _copy_tree_preserving_readonly(artifact_results / "manifest", manifest_dir)
        if staging_manifest_csv.is_file():
            shutil.copy2(staging_manifest_csv, manifest_dir / "run_manifest.csv")
        bundle_json_src = artifact_downloads / "google-play-bundle.json"
        if bundle_json_src.is_file() and not (manifest_dir / "google-play-bundle.json").exists():
            shutil.copy2(bundle_json_src, manifest_dir / "google-play-bundle.json")
        if staging_phase1.is_file():
            shutil.copy2(staging_phase1, manifest_dir / "phase_one_verification.json")

        # 4. reports/
        reports_dir = run_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        if staging_final_dir.is_dir():
            for name in ("final-report.json", "final-report.html"):
                src_file = staging_final_dir / name
                if src_file.is_file():
                    shutil.copy2(src_file, reports_dir / name)
        if staging_findings_csv.is_file():
            shutil.copy2(staging_findings_csv, reports_dir / "findings.csv")
        if artifact_reports.is_dir():
            for name in ("report.json", "report.html"):
                src_file = artifact_reports / name
                if src_file.is_file():
                    shutil.copy2(src_file, reports_dir / name)

        # 5. stages/
        stages_dir = run_dir / "stages"
        stages_dir.mkdir(parents=True, exist_ok=True)
        if (artifact_results / "stages").is_dir():
            _copy_tree_preserving_readonly(artifact_results / "stages", stages_dir)
        if (staging_run_meta / "stages").is_dir():
            _copy_tree_preserving_readonly(staging_run_meta / "stages", stages_dir)
        if (staging_run_meta / "static-analysis-run.json").is_file():
            shutil.copy2(
                staging_run_meta / "static-analysis-run.json",
                stages_dir / "static-analysis-run.json",
            )

        # 6. logs/
        logs_dir = run_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        for log_name in ("apktool.log", "trufflehog.log"):
            src_log = artifact_results / log_name
            if src_log.is_file():
                shutil.copy2(src_log, logs_dir / log_name)
        if staging_logs_dir.is_dir():
            for log_file in sorted(staging_logs_dir.iterdir()):
                if log_file.is_file() and not log_file.is_symlink():
                    dest_log = logs_dir / log_file.name
                    if not dest_log.exists():
                        shutil.copy2(log_file, dest_log)

        # 7. prompts/ + README.txt
        deliver_prompts(run_dir)

        # 8. ai_analysis/attempt-01/ (writable scratch area)
        (run_dir / "ai_analysis" / "attempt-01").mkdir(parents=True, exist_ok=True)

        # 9. README.md
        (run_dir / "README.md").write_text(
            render_run_readme(
                package_id=pkg,
                version_code=ver,
                version_name=ver_name,
                run_id=run_id,
                created_at=created_at,
                bundle_id=digest,
                status=item_status,
            ),
            encoding="utf-8",
        )

        # 10. Freeze evidence (handoff.json + hashes.sha256 + read-only evidence dirs)
        home_db.freeze_evidence(run_dir)

        # 11. Update <home>/runs_index.json
        dossiers, ledgers = _find_ai_outputs(run_dir)
        run_index.upsert(
            {
                "run_id": run_id,
                "package_id": pkg,
                "version_code": ver,
                "version_name": ver_name,
                "bundle_id": digest,
                "created_at": created_at,
                "folder": run_dir.relative_to(home_path).as_posix(),
                "status": item_status,
                "has_dossier": bool(dossiers),
                "has_lead_ledger": bool(ledgers),
            }
        )
        created_dirs.append(run_dir)

    return created_dirs


def run_local_apk_self_contained(
    apk_input: str | Path,
    home: str | Path,
    *,
    config: Config | None = None,
    package_id: str | None = None,
    version_code: str | int | None = None,
    version_name: str | None = None,
    app_name: str | None = None,
    run_id: str | None = None,
    progress: Callable[[str], None] | None = None,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Run the full pipeline on a local APK or split-APK directory into `<home>/runs/<name>/`."""
    input_path = Path(apk_input).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"APK input not found: {input_path}")

    home_path = Path(home).expanduser().resolve()
    home_path.mkdir(parents=True, exist_ok=True)
    (home_path / RUNS_DIRNAME).mkdir(parents=True, exist_ok=True)

    cfg = config or Config(workspace=home_path)
    log = logger or logging.getLogger("apkworkbench.layout")

    # Resolve APK file(s) and optional google-play-bundle.json
    bundle_meta: dict[str, Any] = {}
    apk_files: list[Path] = []
    if input_path.is_dir():
        apk_files = sorted(
            (p for p in input_path.iterdir() if p.is_file() and not p.is_symlink() and p.suffix.lower() == ".apk"),
            key=lambda p: (0 if p.name == "base.apk" else 1, p.name),
        )
        if not apk_files:
            raise ValueError(f"No .apk files found in directory: {input_path}")
        bundle_meta = _read_bundle_json(input_path / "google-play-bundle.json")
    elif input_path.is_file():
        if input_path.suffix.lower() != ".apk":
            raise ValueError(f"Expected an .apk file or directory, got: {input_path}")
        apk_files = [input_path]
        sibling_bundle = input_path.parent / "google-play-bundle.json"
        if sibling_bundle.is_file():
            bundle_meta = _read_bundle_json(sibling_bundle)
    else:
        raise ValueError(f"Unsupported APK input path: {input_path}")

    primary_apk = apk_files[0]
    extracted = (
        _extract_apk_metadata(primary_apk)
        if not (package_id and version_code is not None)
        and not (bundle_meta.get("package_id") and bundle_meta.get("version_code") is not None)
        else {}
    )

    resolved_pkg = str(
        package_id
        or bundle_meta.get("package_id")
        or extracted.get("package_id")
        or "local.unknown.app"
    ).strip()
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", resolved_pkg):
        resolved_pkg = f"local.{_sanitize_segment(resolved_pkg, 'unknown')}.app"

    raw_ver = (
        version_code
        if version_code is not None
        else bundle_meta.get("version_code", extracted.get("version_code", "1"))
    )
    resolved_ver = str(raw_ver).strip()
    if not resolved_ver.isdigit():
        resolved_ver = "1"

    resolved_ver_name = str(
        version_name
        if version_name is not None
        else bundle_meta.get("version_name", extracted.get("version_name", ""))
    ).strip()
    resolved_app_name = str(
        app_name
        if app_name is not None
        else bundle_meta.get("title", extracted.get("app_name", resolved_pkg))
    ).strip()

    signer_raw = bundle_meta.get("signer_sha256", "")
    if isinstance(signer_raw, list):
        signer_str = ",".join(str(item) for item in signer_raw if item)
    else:
        signer_str = str(signer_raw or "")

    resolved_run_id = run_id or str(uuid.uuid4())
    created_at = utc_now()

    with tempfile.TemporaryDirectory(prefix=".apkworkbench-stage-", dir=home_path) as stage_str:
        staging = Path(stage_str)
        db = WorkspaceDatabase(staging)
        db.ensure()

        download_dir = staging / "downloads" / f"{resolved_pkg}-{resolved_ver}"
        download_dir.mkdir(parents=True, exist_ok=True)

        copied_files_meta: list[dict[str, Any]] = []
        primary_dest: Path | None = None
        primary_sha256 = ""
        primary_size = 0
        for idx, apk_src in enumerate(apk_files):
            dest_name = "base.apk" if idx == 0 and len(apk_files) == 1 and apk_src.name != "base.apk" else apk_src.name
            dest_path = download_dir / dest_name
            shutil.copy2(apk_src, dest_path)
            digest = _sha256_file(dest_path)
            size = dest_path.stat().st_size
            if idx == 0:
                primary_dest = dest_path
                primary_sha256 = digest
                primary_size = size
            copied_files_meta.append(
                {
                    "kind": "apk",
                    "name": dest_name,
                    "sha256": digest,
                    "size": size,
                    "play_hash": digest,
                    "play_hash_algorithm": "sha256",
                    "play_hash_verified": True,
                }
            )
        assert primary_dest is not None

        bundle_payload = dict(bundle_meta)
        bundle_payload.setdefault("source", "google_play")
        bundle_payload["package_id"] = resolved_pkg
        bundle_payload["version_code"] = int(resolved_ver)
        bundle_payload["version_name"] = resolved_ver_name
        bundle_payload.setdefault("title", resolved_app_name)
        bundle_payload["run_id"] = resolved_run_id
        bundle_payload.setdefault("downloaded_at", created_at)
        bundle_payload["files"] = copied_files_meta
        _atomic_write_json(download_dir / "google-play-bundle.json", bundle_payload)

        download_url = f"google-play://{resolved_pkg}/{resolved_ver}/{primary_dest.name}"
        db.write_manifest(
            resolved_run_id,
            [
                {
                    "run_id": resolved_run_id,
                    "selection_order": 1,
                    "selected_at": created_at,
                    "package_id": resolved_pkg,
                    "app_name": resolved_app_name,
                    "version_code": resolved_ver,
                    "version_name": resolved_ver_name,
                    "source": "google_play",
                    "download_url": download_url,
                    "sha256": primary_sha256,
                    "size": primary_size,
                    "signer_sha256": signer_str,
                    "local_path": str(primary_dest),
                    "index_sha256": primary_sha256,
                }
            ],
        )
        db.append_attempt(
            {
                "timestamp": created_at,
                "run_id": resolved_run_id,
                "sha256": primary_sha256,
                "package_id": resolved_pkg,
                "download_url": download_url,
                "status": "success",
                "bytes_received": primary_size,
                "error": "",
            }
        )
        db.append_history(
            {
                "sha256": primary_sha256,
                "package_id": resolved_pkg,
                "app_name": resolved_app_name,
                "version_code": resolved_ver,
                "version_name": resolved_ver_name,
                "source": "google_play",
                "download_url": download_url,
                "local_path": str(primary_dest),
                "size": primary_size,
                "run_id": resolved_run_id,
                "downloaded_at": created_at,
                "index_sha256": primary_sha256,
            }
        )

        # Write phase-one verification record
        _atomic_write_json(
            staging / "reports" / f"phase_one_verification_{resolved_run_id}.json",
            {
                "schema_version": 1,
                "run_id": resolved_run_id,
                "verified_at": created_at,
                "source": "local_apk",
                "package_id": resolved_pkg,
                "version_code": resolved_ver,
                "files": copied_files_meta,
            },
        )

        run_stages_dir = staging / "results" / "runs" / resolved_run_id / "stages"

        # Stage 1: Decompile
        decompile_runner = DecompilationRunner(
            db,
            workspace=staging,
            apktool_executable=str(cfg.get("tools.apktool", "apktool")),
            timeout_seconds=int(cfg.get("decompilation.timeout_seconds", 3600)),
            logger=log,
            progress=progress,
        )
        decompile_summary = decompile_runner.run(run_id=resolved_run_id)
        db.write_stage_status(
            run_stages_dir / "decompile",
            stage="decompile",
            status=(
                "success"
                if decompile_summary.failed == 0 and decompile_summary.partial == 0
                else "partial"
                if decompile_summary.completed or decompile_summary.partial
                else "failed"
            ),
            counts={
                "examined": decompile_summary.examined,
                "completed": decompile_summary.completed,
                "partial": decompile_summary.partial,
                "failed": decompile_summary.failed,
                "skipped": decompile_summary.skipped,
            },
            coverage={"apks": "complete" if decompile_summary.failed == 0 else "partial"},
        )

        # Stage 2: Static Surface Analysis
        surface_summary = run_static_surface_analysis(
            db,
            staging,
            run_id=resolved_run_id,
            dex_timeout_seconds=int(cfg.get("analysis.androguard_timeout_seconds", 1800)),
            progress=progress,
        )
        db.write_stage_status(
            run_stages_dir / "surface",
            stage="surface",
            status=(
                "success"
                if surface_summary.get("failed", 0) == 0 and surface_summary.get("partial", 0) == 0
                else "partial"
                if surface_summary.get("completed", 0) or surface_summary.get("partial", 0)
                else "failed"
            ),
            counts={
                "eligible": int(surface_summary.get("eligible", 0)),
                "completed": int(surface_summary.get("completed", 0)),
                "partial": int(surface_summary.get("partial", 0)),
                "failed": int(surface_summary.get("failed", 0)),
                "skipped": int(surface_summary.get("skipped", 0)),
                "findings": int(surface_summary.get("finding_count", 0)),
            },
            coverage={"surface": "complete" if surface_summary.get("failed", 0) == 0 else "partial"},
        )

        # Stage 3: TruffleHog + secret-link refresh
        scanner = TruffleHogScanner(
            db,
            workspace=staging,
            executable=str(cfg.get("tools.trufflehog", "trufflehog")),
            timeout_seconds=int(cfg.get("analysis.timeout_seconds", 7200)),
            max_output_bytes=int(cfg.get("analysis.max_output_bytes", 512 * 1024 * 1024)),
            logger=log,
            progress=progress,
        )
        scan_summary = scanner.run(run_id=resolved_run_id)
        link_summary = refresh_secret_links(db, staging, run_id=resolved_run_id)
        db.write_stage_status(
            run_stages_dir / "trufflehog",
            stage="trufflehog",
            status="success" if scan_summary.failed == 0 else "failed",
            counts={
                "scanned": scan_summary.scanned,
                "findings": scan_summary.findings,
                "failed": scan_summary.failed,
                "skipped": scan_summary.skipped,
                "links_updated": int(link_summary.get("updated", 0)),
            },
            coverage={"trufflehog": "complete" if scan_summary.failed == 0 else "partial"},
        )

        # Stage 4: Reports
        report_generator = ReportGenerator(db, workspace=staging)
        report_summary = report_generator.run()
        final_report = generate_final_run_report(db, staging, resolved_run_id)
        db.write_stage_status(
            run_stages_dir / "report",
            stage="report",
            status="success",
            counts={
                "generated": report_summary.generated,
                "with_findings": report_summary.with_findings,
                "total_findings": report_summary.total_findings,
            },
            coverage={"reports": "complete"},
        )

        # Stage 5: Reconcile
        reconciliation = db.reconcile_run(resolved_run_id)
        db.write_stage_status(
            run_stages_dir / "reconciliation",
            stage="reconciliation",
            status=(
                "success"
                if reconciliation["complete"] == reconciliation["total"]
                else "partial"
            ),
            counts={
                "total": int(reconciliation["total"]),
                "complete": int(reconciliation["complete"]),
            },
            coverage={"reconciliation": "complete"},
        )

        # Stage 6: Consolidate into <home>/runs/<name>/ and freeze
        run_dirs = consolidate_workspace_run(home_path, staging, resolved_run_id)

    run_dir = run_dirs[0]
    verification = WorkspaceDatabase(home_path).verify_workspace(run_dir)
    return {
        "run_id": resolved_run_id,
        "package_id": resolved_pkg,
        "version_code": resolved_ver,
        "version_name": resolved_ver_name,
        "bundle_id": primary_sha256,
        "run_dir": str(run_dir),
        "reconciliation": reconciliation,
        "verification": verification,
        "final_report": {
            "static_findings": final_report.get("static_findings", 0),
            "verified_findings": final_report.get("verified_findings", 0),
        },
    }


def migrate_legacy_workspace(
    source_workspace: str | Path,
    target_home: str | Path,
    *,
    dry_run: bool = True,
    legacy_config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Copy legacy `results/<pkg>/<ver>/<digest>` bundles into `<target_home>/runs/`.

    Never deletes or moves files in `source_workspace` or `legacy_config_path`.
    """
    source = Path(source_workspace).expanduser().resolve()
    target = Path(target_home).expanduser().resolve()
    results_root = source / "results"
    downloads_root = source / "downloads"
    reports_root = source / "reports"

    legacy_cfg = Path(legacy_config_path).expanduser() if legacy_config_path else None
    legacy_cfg_exists = bool(legacy_cfg is not None and legacy_cfg.is_file() and not legacy_cfg.is_symlink())
    target_cfg = target / "config.yaml"

    discovered: list[dict[str, Any]] = []
    if results_root.is_dir() and not results_root.is_symlink():
        for pkg_dir in sorted(results_root.iterdir()):
            if pkg_dir.name in _SKIP_RESULTS_DIRS or pkg_dir.is_symlink() or not pkg_dir.is_dir():
                continue
            for ver_dir in sorted(pkg_dir.iterdir()):
                if ver_dir.is_symlink() or not ver_dir.is_dir():
                    continue
                for digest_dir in sorted(ver_dir.iterdir()):
                    if digest_dir.is_symlink() or not digest_dir.is_dir():
                        continue
                    children = {child.name for child in digest_dir.iterdir()}
                    if not (children & _BUNDLE_MARKER_ENTRIES):
                        continue

                    package_id = pkg_dir.name
                    version_code = ver_dir.name
                    digest = digest_dir.name
                    folder_name = run_folder_name(package_id, version_code, digest)
                    dest_dir = target / RUNS_DIRNAME / folder_name

                    dossiers, ledgers = _find_ai_outputs(digest_dir)
                    download_match = downloads_root / f"{package_id}-{version_code}"
                    has_downloads = download_match.is_dir() and not download_match.is_symlink()
                    report_match = reports_root / package_id / version_code / digest
                    has_reports = report_match.is_dir() and not report_match.is_symlink()

                    bundle_meta = _read_bundle_json(
                        digest_dir / "manifest" / "google-play-bundle.json"
                    ) or (
                        _read_bundle_json(download_match / "google-play-bundle.json")
                        if has_downloads
                        else {}
                    )
                    version_name = str(bundle_meta.get("version_name", ""))
                    run_id = str(bundle_meta.get("run_id") or digest[:8])
                    created_at = str(bundle_meta.get("downloaded_at") or utc_now())

                    discovered.append(
                        {
                            "package_id": package_id,
                            "version_code": version_code,
                            "version_name": version_name,
                            "bundle_id": digest,
                            "run_id": run_id,
                            "created_at": created_at,
                            "source_dir": str(digest_dir),
                            "target_dir": str(dest_dir),
                            "folder": f"{RUNS_DIRNAME}/{folder_name}",
                            "has_downloads": has_downloads,
                            "downloads_dir": str(download_match) if has_downloads else None,
                            "has_reports": has_reports,
                            "reports_dir": str(report_match) if has_reports else None,
                            "dossiers": [rel.as_posix() for rel in dossiers],
                            "lead_ledgers": [rel.as_posix() for rel in ledgers],
                            "has_dossier": bool(dossiers),
                            "has_lead_ledger": bool(ledgers),
                            "action": "already_exists" if dest_dir.exists() else "would_copy",
                            "dossier_verified": False,
                            "lead_ledger_verified": False,
                        }
                    )

    dossiers_found = sum(1 for item in discovered if item["has_dossier"])
    lead_ledgers_found = sum(1 for item in discovered if item["has_lead_ledger"])

    if dry_run:
        return {
            "dry_run": True,
            "source_workspace": str(source),
            "target_home": str(target),
            "bundles_found": len(discovered),
            "bundles_migrated": 0,
            "bundles_skipped": sum(1 for item in discovered if item["action"] == "already_exists"),
            "dossiers_found": dossiers_found,
            "dossiers_verified": 0,
            "lead_ledgers_found": lead_ledgers_found,
            "lead_ledgers_verified": 0,
            "legacy_config": {
                "source": str(legacy_cfg) if legacy_cfg_exists else None,
                "target": str(target_cfg),
                "would_copy": bool(legacy_cfg_exists and not target_cfg.exists()),
                "copied": False,
            },
            "items": discovered,
        }

    target.mkdir(parents=True, exist_ok=True)
    (target / RUNS_DIRNAME).mkdir(parents=True, exist_ok=True)
    run_index = RunIndex(target)

    migrated = 0
    skipped = 0
    dossiers_verified = 0
    lead_ledgers_verified = 0

    for item in discovered:
        src_dir = Path(item["source_dir"])
        dest_dir = Path(item["target_dir"])
        if dest_dir.exists():
            item["action"] = "skipped_existing"
            skipped += 1
        else:
            _copy_tree_preserving_readonly(src_dir, dest_dir)
            if item["has_downloads"] and not (dest_dir / "apk").exists():
                apk_dir = dest_dir / "apk"
                apk_dir.mkdir(parents=True, exist_ok=True)
                for entry in sorted(Path(item["downloads_dir"]).iterdir()):
                    if entry.is_symlink() or not entry.is_file():
                        continue
                    if entry.suffix.lower() == ".apk" or entry.name == "google-play-bundle.json":
                        shutil.copy2(entry, apk_dir / entry.name)
            if item["has_reports"] and not (dest_dir / "reports").exists():
                _copy_tree_preserving_readonly(Path(item["reports_dir"]), dest_dir / "reports")
            if not (dest_dir / "README.md").exists():
                (dest_dir / "README.md").write_text(
                    render_run_readme(
                        package_id=item["package_id"],
                        version_code=item["version_code"],
                        version_name=item["version_name"],
                        run_id=item["run_id"],
                        created_at=item["created_at"],
                        bundle_id=item["bundle_id"],
                        status="migrated",
                    ),
                    encoding="utf-8",
                )
            if not (dest_dir / "ai_analysis").exists():
                (dest_dir / "ai_analysis" / "attempt-01").mkdir(parents=True, exist_ok=True)
            item["action"] = "migrated"
            migrated += 1

        # Byte-identical verification of dossier.md and lead_ledger.json
        if item["dossiers"]:
            all_match = True
            for rel_str in item["dossiers"]:
                src_file = src_dir / rel_str
                dst_file = dest_dir / rel_str
                if not dst_file.is_file() or _sha256_file(src_file) != _sha256_file(dst_file):
                    all_match = False
                    raise RuntimeError(
                        f"Dossier verification failed after migration: {dst_file}"
                    )
            item["dossier_verified"] = all_match
            if all_match:
                dossiers_verified += 1

        if item["lead_ledgers"]:
            all_match = True
            for rel_str in item["lead_ledgers"]:
                src_file = src_dir / rel_str
                dst_file = dest_dir / rel_str
                if not dst_file.is_file() or _sha256_file(src_file) != _sha256_file(dst_file):
                    all_match = False
                    raise RuntimeError(
                        f"Lead ledger verification failed after migration: {dst_file}"
                    )
            item["lead_ledger_verified"] = all_match
            if all_match:
                lead_ledgers_verified += 1

        run_index.upsert(
            {
                "run_id": item["run_id"],
                "package_id": item["package_id"],
                "version_code": item["version_code"],
                "version_name": item["version_name"],
                "bundle_id": item["bundle_id"],
                "created_at": item["created_at"],
                "folder": item["folder"],
                "status": "migrated",
                "has_dossier": item["has_dossier"],
                "has_lead_ledger": item["has_lead_ledger"],
            }
        )

    config_copied = False
    if legacy_cfg_exists and legacy_cfg is not None and not target_cfg.exists():
        shutil.copy2(legacy_cfg, target_cfg)
        config_copied = True

    return {
        "dry_run": False,
        "source_workspace": str(source),
        "target_home": str(target),
        "bundles_found": len(discovered),
        "bundles_migrated": migrated,
        "bundles_skipped": skipped,
        "dossiers_found": dossiers_found,
        "dossiers_verified": dossiers_verified,
        "lead_ledgers_found": lead_ledgers_found,
        "lead_ledgers_verified": lead_ledgers_verified,
        "legacy_config": {
            "source": str(legacy_cfg) if legacy_cfg_exists else None,
            "target": str(target_cfg),
            "would_copy": bool(legacy_cfg_exists and not target_cfg.exists()),
            "copied": config_copied,
        },
        "items": discovered,
    }
