"""APK Workbench command-line entry point."""
import csv
import os
import tempfile
import hashlib
import json
import re
import uuid
from functools import wraps
from pathlib import Path

import click

from apkworkbench import __version__
from apkworkbench.acquisition.verification import (
    AcquisitionVerificationError,
    verify_google_play_run,
)
from apkworkbench.analysis.trufflehog import AnalysisError, TruffleHogScanner
from apkworkbench.analysis.apk_surface import (
    refresh_secret_links,
    run_static_surface_analysis,
)
from apkworkbench.analysis.surface.handoff import PROMPT_FILES, prompts_source_dir
from apkworkbench.core.config import Config
from apkworkbench.core.layout import (
    migrate_legacy_workspace,
    run_local_apk_self_contained,
)
from apkworkbench.core.logging import setup_logging
from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase, utc_now
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.reporting.generator import ReportGenerator, ReportingError
from apkworkbench.reporting.final_run import FinalRunReportError, generate_final_run_report
from apkworkbench.dependencies.detector import DependencyDetector
from apkworkbench.sources.google_play import (
    GooglePlayError,
    GooglePlaySource,
    GooglePlayUnavailableError,
    PlayApp,
)
from apkworkbench.sources.google_play_anonymous import (
    describe_auth_mode,
)


def _play_auth_mode(config: Config) -> str:
    """Resolve the configured Google Play authentication mode (validated in Config)."""
    return str(config.get("sources.google_play.auth_mode", "auto"))


def _source_auth_mode(config: Config) -> str:
    """AuthMode accepted by the Play source/session layer (fails on bad config)."""
    mode = _play_auth_mode(config)
    try:
        from apkworkbench.sources.google_play_anonymous import validate_auth_mode

        return validate_auth_mode(mode)
    except ValueError as exc:
        raise click.ClickException(f"Invalid auth_mode configuration: {exc}") from exc


def _doctor_auth_report(config: Config) -> dict:
    """Summarize the current Play session source without touching any token."""
    return describe_auth_mode(_source_auth_mode(config))


def _load_config(workspace: str | Path | None = None) -> Config:
    """Instantiate Config, applying a CLI --workspace override only when supplied."""
    override = workspace
    if override is None:
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            override = ctx.meta.get("apkworkbench_workspace")
    if override is not None:
        return Config(workspace=override)
    return Config()


def _workspace_locked(command):
    """Hold the workspace process lock for each command and the full pipeline."""
    @wraps(command)
    def wrapped(*args, **kwargs):
        workspace = kwargs.get("workspace") or _load_config().get("workspace")
        database = WorkspaceDatabase(workspace)
        with database._write_lock():
            return command(*args, **kwargs)

    return wrapped


BANNER = """APK WORKBENCH
DISCOVER | DOWNLOAD | DECOMPILE | ANALYZE | CATALOGUE
CO-DEVELOPED BY dial9 + ChatGPT
SLOW. SIMPLE. SEQUENTIAL. VERIFIED."""


def _catalog_path(config: Config) -> Path:
    return Path(config.get("workspace")).expanduser() / "database" / "google_play_discovery.csv"


def _write_catalog(
    path: Path,
    apps: list[PlayApp],
    channels: dict[str, tuple[str, str]] | None = None,
) -> None:
    """Write the discovery catalog; channels maps pkg -> (channel, discovered_at)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=".google-play-discovery.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        fieldnames = [
            "package_id", "title", "developer", "version_name", "version_code",
            "discovery_channel", "discovery_time",
        ]
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for app in apps:
                channel_entry = (channels or {}).get(app.package_id) or ("", "")
                writer.writerow({
                    "package_id": app.package_id,
                    "title": app.title,
                    "developer": app.developer,
                    "version_name": app.version_name,
                    "version_code": app.version_code,
                    "discovery_channel": channel_entry[0],
                    "discovery_time": channel_entry[1],
                })
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


def _read_catalog(path: Path) -> list[PlayApp]:
    if path.is_symlink():
        raise click.ClickException(f"Refusing symlinked Google Play catalog: {path}")
    if not path.is_file():
        raise click.ClickException(
            f"Google Play discovery catalog not found: {path}. Run 'apkworkbench discover' first."
        )
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [
            PlayApp(
                package_id=row["package_id"],
                title=row.get("title") or row["package_id"],
                developer=row.get("developer") or "",
                version_name=row.get("version_name") or "",
                version_code=int(row.get("version_code") or 0),
            )
            for row in csv.DictReader(handle)
            if row.get("package_id")
        ]


def _read_catalog_channels(path: Path) -> dict[str, tuple[str, str]]:
    """Read discovery provenance columns; missing columns (legacy files) become blanks."""
    if path.is_symlink() or not path.is_file():
        return {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        return {
            row["package_id"]: (
                row.get("discovery_channel") or "",
                row.get("discovery_time") or "",
            )
            for row in csv.DictReader(handle)
            if row.get("package_id")
        }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plan_digest(plan) -> str:
    value = {
        "source": "google_play",
        "package_id": plan.app.package_id,
        "version_code": plan.app.version_code,
        "files": [
            {"name": item.name, "size": item.size, "sha256": item.sha256}
            for item in plan.files if item.kind == "apk"
        ],
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read_json_object(path: Path) -> dict:
    if path.is_symlink():
        raise DatabaseError(f"Refusing symlinked stage evidence: {path}")
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DatabaseError(f"Cannot read stage evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DatabaseError(f"Stage evidence must contain a JSON object: {path}")
    return value


def _object_rows(value: object, *, label: str) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise DatabaseError(f"{label} must contain a list of JSON objects.")
    return value


def _stage_diagnostics(message: str, code: str) -> list[dict[str, str]]:
    return [{"code": code, "message": message}] if message else []


def _status_message(stage: str, status: str, message: str) -> str:
    if message:
        return message
    return {
        "failed": f"{stage} stage failed without a specific error.",
        "partial": f"{stage} stage completed with partial coverage.",
        "running": f"{stage} stage did not reach a terminal outcome.",
        "not_run": f"{stage} stage was not run.",
        "skipped": f"{stage} stage was skipped.",
    }.get(status, "")


def _trufflehog_stage_outcome(
    bundle: Path,
    processing: dict[str, str],
) -> tuple[str, dict[str, int], str]:
    status = processing.get("scan_status") or "not_run"
    scan = _read_json_object(bundle / "trufflehog" / "scan.json")
    counts = {
        key: scan.get(key, 0)
        for key in ("total_seen", "verified", "unverified")
    }
    if status != "success":
        return status, {
            key: value if type(value) is int and value >= 0 else 0
            for key, value in counts.items()
        }, processing.get("error", "") if status == "failed" else ""

    required_files = (
        "findings.json",
        "findings-verified.json",
        "findings-unverified.json",
    )
    complete_files = all(
        (bundle / "trufflehog" / name).is_file()
        and not (bundle / "trufflehog" / name).is_symlink()
        for name in required_files
    )
    valid_counts = all(type(value) is int and value >= 0 for value in counts.values())
    counts_consistent = (
        valid_counts
        and counts["total_seen"] == counts["verified"] + counts["unverified"]
    )
    if not scan or not complete_files or not counts_consistent:
        return (
            "partial",
            {
                key: value if type(value) is int and value >= 0 else 0
                for key, value in counts.items()
            },
            "TruffleHog is marked successful but its summary or complete split outputs are missing or inconsistent.",
        )
    return "success", counts, ""


def _write_bundle_stage_statuses(
    database: WorkspaceDatabase,
    workspace: str | Path,
    run_id: str,
    *,
    pipeline_issues: list[str] | None = None,
) -> dict[str, int]:
    """Persist per-artifact outcomes outside decoded APK content."""
    root = Path(workspace).expanduser().resolve()
    results_root = root / "results"
    manifest = database.read_manifest(run_id)
    history = database.read_download_history()
    history_by_hash = {
        row.get("sha256", "").lower(): row for row in history if row.get("sha256")
    }
    processing = database.read_processing_status()
    issue_set = set(pipeline_issues or [])
    verification = _read_json_object(
        root / "reports" / f"phase_one_verification_{run_id}.json"
    )
    verified_components: set[tuple[str, str, str]] = set()
    for item in _object_rows(
        verification.get("bundles", []), label="Verification bundles"
    ):
        component_hashes = item.get("sha256")
        if not isinstance(component_hashes, list) or not all(
            isinstance(value, str) for value in component_hashes
        ):
            raise DatabaseError("Verification bundle SHA-256 values are malformed.")
        verified_components.update(
            (
                str(item.get("package_id", "")),
                str(item.get("version_code", "")),
                value.lower(),
            )
            for value in component_hashes
        )
    surface_run = _read_json_object(
        results_root / "runs" / run_id / "static-analysis-run.json"
    )
    surface_by_digest = {
        str(item.get("sha256", "")).lower(): item
        for item in _object_rows(
            surface_run.get("artifacts", []), label="Surface artifacts"
        )
    }
    counts = {"bundles": 0, "statuses_written": 0, "frozen_skipped": 0, "missing": 0}
    for selected in manifest:
        package_id = selected["package_id"]
        version_code = str(selected["version_code"])
        digest = selected["sha256"].lower()
        bundle = results_root / package_id / version_code / digest
        if not bundle.is_dir():
            counts["missing"] += 1
            continue
        counts["bundles"] += 1
        if (bundle / "hashes.sha256").is_file():
            counts["frozen_skipped"] += 1
            continue

        acquired = history_by_hash.get(digest, {})
        downloaded = (
            acquired.get("run_id") == run_id
            and acquired.get("package_id") == package_id
            and str(acquired.get("version_code", "")) == version_code
        )
        verification_ok = (
            verification.get("status") == "verified"
            and (package_id, version_code, digest) in verified_components
        )
        verification_status = (
            "success" if verification_ok
            else "failed" if "download_verification" in issue_set or verification
            else "not_run"
        )
        process = processing.get(digest, {})
        surface = surface_by_digest.get(digest, {})
        surface_status = {
            "success": "success",
            "partial": "partial",
            "failed": "failed",
            "skipped_reused": "success",
        }.get(surface.get("status"), "not_run")
        if "surface" in issue_set and surface_status == "running":
            surface_status = "failed"
        if "surface" in issue_set and surface_status == "not_run":
            surface_status = "failed"
        trufflehog_status, trufflehog_counts, trufflehog_diagnostic = (
            _trufflehog_stage_outcome(bundle, process)
        )
        for stage, status, stage_counts, diagnostic in (
            (
                "download",
                "success" if downloaded else "failed",
                {"apk_components": 1 if downloaded else 0},
                "" if downloaded else "No matching acquisition record for this run.",
            ),
            (
                "verification",
                verification_status,
                {"verified_components": int(verification_ok)},
                "" if verification_ok else (
                    "Run verification failed."
                    if verification_status == "failed"
                    else "APK component was not verified in this run."
                ),
            ),
            (
                "decompile",
                process.get("apktool_status") or "not_run",
                {"artifacts": 1},
                process.get("error", ""),
            ),
            (
                "surface",
                surface_status,
                {
                    "findings": int(surface.get("finding_count", 0) or 0),
                    "artifacts": 1 if surface else 0,
                },
                surface.get("error", ""),
            ),
            (
                "trufflehog",
                trufflehog_status,
                trufflehog_counts,
                trufflehog_diagnostic,
            ),
        ):
            diagnostic = _status_message(stage, str(status), str(diagnostic))
            diagnostics = _stage_diagnostics(
                diagnostic,
                f"{stage}_incomplete" if status != "success" else "",
            )
            database.write_stage_status(
                bundle / "stages" / stage,
                stage=stage,
                status=str(status),
                counts=stage_counts,
                coverage={"artifacts": "complete" if status == "success" else str(status)},
                diagnostics=diagnostics,
            )
            counts["statuses_written"] += 1
    return counts


def _write_run_stage_statuses(
    database: WorkspaceDatabase,
    workspace: str | Path,
    run_id: str,
    *,
    reconciliation: dict | None,
    reconciliation_error: str = "",
    frozen: int = 0,
    freeze_issues: int = 0,
    pipeline_issues: list[str] | None = None,
) -> None:
    root = Path(workspace).expanduser().resolve()
    manifest = database.read_manifest(run_id)
    issue_set = set(pipeline_issues or [])
    processing = database.read_processing_status()
    marker = _read_json_object(
        root / "results" / "runs" / run_id / "static-analysis-run.json"
    )
    verification = _read_json_object(
        root / "reports" / f"phase_one_verification_{run_id}.json"
    )
    report_dir = root / "reports" / "runs" / run_id
    report_ready = all(
        (report_dir / name).is_file() and not (report_dir / name).is_symlink()
        for name in ("final-report.json", "final-report.html")
    )
    statuses = [processing.get(row["sha256"].lower(), {}) for row in manifest]
    decompile_counts = {
        state: sum(row.get("apktool_status") == state for row in statuses)
        for state in ("success", "partial", "failed", "running")
    }
    scan_outcomes = [
        _trufflehog_stage_outcome(
            root / "results" / row["package_id"] / str(row["version_code"])
            / row["sha256"].lower(),
            state,
        )[0]
        for row, state in zip(manifest, statuses, strict=True)
    ]
    scan_counts = {
        state: sum(outcome == state for outcome in scan_outcomes)
        for state in ("success", "partial", "failed", "running", "not_run")
    }
    surface_total = sum(
        int(marker.get(key, 0) or 0)
        for key in ("completed", "partial", "failed", "skipped")
    )
    reconciliation_ok = (
        reconciliation is not None
        and int(reconciliation.get("complete", 0)) == int(reconciliation.get("total", -1))
    )
    reconciliation_warnings = (
        int(reconciliation.get("counts", {}).get("complete_with_warnings", 0) or 0)
        if reconciliation
        else 0
    )
    reconciliation_status = (
        "partial" if reconciliation_ok and reconciliation_warnings
        else "success" if reconciliation_ok
        else "failed"
    )
    download_status = (
        "partial" if "download" in issue_set and manifest
        else "failed" if "download" in issue_set or not manifest
        else "success"
    )
    verification_status = (
        "failed" if "download_verification" in issue_set
        else "success" if verification.get("status") == "verified"
        else "not_run"
    )
    surface_status = str(marker.get("status", "not_run"))
    if "surface" in issue_set and surface_status in {"running", "not_run"}:
        surface_status = "failed"
    if "no_usable_apktool_output" in issue_set:
        trufflehog_status = "skipped"
    elif scan_counts["success"] == len(manifest) and manifest:
        trufflehog_status = "success"
    elif not any(scan_counts.values()):
        trufflehog_status = "not_run"
    else:
        trufflehog_status = "partial"
    report_status = (
        "success" if report_ready
        else "failed" if "report" in issue_set
        else "not_run"
    )
    stages = [
        (
            "discover",
            "skipped",
            {"catalogs": 0},
            {"catalog": "not_run"},
            "The run command consumes the saved discovery catalog.",
        ),
        (
            "download",
            download_status,
            {"manifest_entries": len(manifest)},
            {"manifest": "complete" if download_status == "success" else str(download_status)},
            "" if download_status == "success" else "Download did not complete successfully.",
        ),
        (
            "verification",
            verification_status,
            {
                "verified_bundles": int(verification.get("verified_bundles", 0) or 0),
                "apk_components": int(verification.get("apk_components", 0) or 0),
            },
            {"apk_components": "complete" if verification_status == "success" else str(verification_status)},
            "" if verification_status == "success" else "Run verification did not complete successfully.",
        ),
        (
            "decompile",
            "success" if decompile_counts["success"] == len(manifest) and manifest else "partial",
            decompile_counts,
            {"artifacts": "complete" if decompile_counts["success"] == len(manifest) else "partial"},
            "",
        ),
        (
            "surface",
            surface_status,
            {
                "eligible": int(marker.get("eligible", 0) or 0),
                "completed": int(marker.get("completed", 0) or 0),
                "partial": int(marker.get("partial", 0) or 0),
                "failed": int(marker.get("failed", 0) or 0),
                "skipped": int(marker.get("skipped", 0) or 0),
                "findings": int(marker.get("finding_count", 0) or 0),
            },
            {"artifacts": "complete" if surface_total >= len(manifest) else "partial"},
            "",
        ),
        (
            "trufflehog",
            trufflehog_status,
            scan_counts,
            {"artifacts": "complete" if trufflehog_status == "success" else str(trufflehog_status)},
            "TruffleHog was skipped because no usable Apktool output was available."
            if trufflehog_status == "skipped"
            else "",
        ),
        (
            "report",
            report_status,
            {"files": 2 if report_ready else 0, "artifacts": len(manifest)},
            {"report_files": "complete" if report_ready else str(report_status)},
            "" if report_ready else "Final JSON and HTML report were not both generated.",
        ),
        (
            "reconciliation",
            reconciliation_status,
            {
                "total": int(reconciliation.get("total", 0) or 0) if reconciliation else 0,
                "complete": int(reconciliation.get("complete", 0) or 0) if reconciliation else 0,
                "warnings": reconciliation_warnings,
            },
            {
                "artifacts": "complete_with_warnings" if reconciliation_warnings
                else "complete" if reconciliation_ok
                else "partial"
            },
            reconciliation_error or (
                f"Run reconciliation completed with {reconciliation_warnings} warning(s)."
                if reconciliation_warnings
                else "" if reconciliation_ok
                else "Run reconciliation did not account for every manifest item."
            ),
        ),
        (
            "freeze",
            "success" if freeze_issues == 0 and frozen == len(manifest) else "partial",
            {"frozen": frozen, "issues": freeze_issues, "manifest_entries": len(manifest)},
            {"bundles": "complete" if freeze_issues == 0 and frozen == len(manifest) else "partial"},
            "",
        ),
    ]
    incomplete_stages = [
        stage for stage, status, *_ in stages
        if stage != "discover" and status != "success"
    ]
    pipeline_messages = list(pipeline_issues or [])
    if incomplete_stages:
        pipeline_messages.append(
            "Stages not fully successful: " + ", ".join(incomplete_stages)
        )
    pipeline_status = "partial" if pipeline_messages else "success"
    stages.append(
        (
            "pipeline",
            pipeline_status,
            {"issues": len(pipeline_messages), "manifest_entries": len(manifest)},
            {"stages": "complete" if pipeline_status == "success" else "partial"},
            "; ".join(pipeline_messages),
        )
    )
    for stage, status, counts, coverage, message in stages:
        message = _status_message(stage, status, message)
        database.write_stage_status(
            root / "results" / "runs" / run_id / "stages" / stage,
            stage=stage,
            status=status,
            counts=counts,
            coverage=coverage,
            diagnostics=_stage_diagnostics(message, f"{stage}_incomplete"),
        )



def _count_usable_apktool_outputs(workspace: str | Path, run_id: str) -> int:
    """Count run-scoped success or partial Apktool outputs safe for TruffleHog."""
    database = WorkspaceDatabase(workspace)
    manifest = database.read_manifest(run_id)
    history = database.read_download_history()
    statuses = database.read_processing_status()
    history_by_hash = {
        row.get("sha256", "").lower(): row for row in history if row.get("sha256")
    }
    root = Path(workspace).expanduser().resolve()
    results_root = root / "results"
    if results_root.is_symlink() or not results_root.is_dir():
        return 0
    results_root = results_root.resolve(strict=True)

    count = 0
    for selected in manifest:
        digest = str(selected.get("sha256", "")).lower()
        package_id = str(selected.get("package_id", ""))
        version_code = str(selected.get("version_code", ""))
        acquired = history_by_hash.get(digest)
        state = statuses.get(digest, {})
        if (
            state.get("apktool_status") not in {"success", "partial"}
            or acquired is None
            or acquired.get("run_id") != run_id
            or acquired.get("source") != selected.get("source")
            or acquired.get("package_id") != package_id
            or str(acquired.get("version_code", "")) != version_code
            or not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id)
            or not version_code.isdigit()
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            continue

        package_root = results_root / package_id
        version_root = package_root / version_code
        artifact_root = version_root / digest
        output = artifact_root / "apktool"
        if any(path.is_symlink() for path in (package_root, version_root, artifact_root, output)):
            continue
        try:
            output.resolve(strict=True).relative_to(results_root)
        except (OSError, ValueError):
            continue
        if DecompilationRunner._has_usable_output(output):
            count += 1
    return count


@click.group()
@click.version_option(__version__, prog_name="apkworkbench")
@click.option(
    "--workspace",
    "workspace_override",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Override the APK-Workbench home folder (default: ~/APK-Workbench or APKWORKBENCH_WORKSPACE).",
)
@click.pass_context
def main(ctx: click.Context, workspace_override: Path | None) -> None:
    """Discover, acquire, decompile, analyze, and catalogue APK files."""
    if workspace_override is not None:
        ctx.meta["apkworkbench_workspace"] = str(workspace_override.expanduser())


@main.command()
def doctor() -> None:
    """Check required external tools, workspace home, bundled prompts, and Play auth."""
    config = _load_config()
    logger = setup_logging(config)
    logger.info("Starting environment check")
    click.echo(BANNER)
    dependencies = DependencyDetector(config).detect_all()
    all_required_ok = True
    for dependency in dependencies:
        click.echo(str(dependency))
        if dependency.required and not (dependency.installed and dependency.healthy):
            all_required_ok = False
            if dependency.error:
                click.echo(f"  {dependency.error}")
            if getattr(dependency, "install_hint", None):
                click.echo(f"  Install: {dependency.install_hint}")

    workspace_path = Path(config.get("workspace")).expanduser()
    workspace_ok = workspace_path.is_dir() and os.access(workspace_path, os.W_OK)
    click.echo(
        f"[{'OK' if workspace_ok else 'MISSING'}] workspace ({workspace_path})"
    )
    if not workspace_ok:
        all_required_ok = False
        click.echo(f"  Workspace directory is missing or not writable: {workspace_path}")
    legacy_cfg = getattr(config, "legacy_config_path", None)
    if legacy_cfg is not None:
        click.echo(
            f"  Note: reading legacy config from {legacy_cfg}; "
            f"move or copy it to {workspace_path / 'config.yaml'} to consolidate."
        )

    prompts_dir = prompts_source_dir()
    prompts_ok = prompts_dir is not None and all(
        (prompts_dir / name).is_file() for name in PROMPT_FILES
    )
    click.echo(
        f"[{'OK' if prompts_ok else 'MISSING'}] prompts "
        f"({prompts_dir if prompts_ok else 'not found'})"
    )
    if not prompts_ok:
        all_required_ok = False
        click.echo(
            "  Shipped AI handoff prompts (0.txt..6.txt) were not found. "
            "Reinstall apkworkbench or set APKWORKBENCH_PROMPTS_DIR."
        )

    auth_report = _doctor_auth_report(config)
    resolved = auth_report.get("resolved_mode")
    if resolved == "account":
        source_text = auth_report.get("account_source") or "resolved"
        email = auth_report.get("account_email") or "***"
        if source_text == "environment-incomplete":
            click.echo("[AUTH] Play session source: INCOMPLETE ACCOUNT CREDENTIALS")
            click.echo("  Set both GOOPDL_ACCOUNT_EMAIL and GOOPDL_AAS_TOKEN, or run `goopdl auth login`.")
        else:
            click.echo(f"[AUTH] Play session source: ACCOUNT ({source_text}; {email})")
    elif resolved == "anonymous" or auth_report.get("configured_mode") == "anonymous":
        click.echo("[AUTH] Play session source: ANONYMOUS (Aurora public token dispenser)")
        click.echo("  The third-party dispenser is often unavailable; run `goopdl auth login` "
                   "and use auth_mode=auto/account for stable acquisition.")
    else:
        configured = auth_report.get("configured_mode") or "auto"
        if configured == "account" or auth_report.get("account_source") in ("none-configured", "saved-account-unreadable"):
            click.echo("[AUTH] Play session source: UNAVAILABLE (no account configured to use)")
            click.echo("  Run `goopdl auth login`, or export GOOPDL_ACCOUNT_EMAIL and GOOPDL_AAS_TOKEN.")
    click.echo("Status: READY" if all_required_ok else "Status: MISSING OR UNHEALTHY REQUIRED DEPENDENCIES")
    if not all_required_ok:
        raise click.exceptions.Exit(1)


@main.command()
@click.option("--query", "queries", multiple=True, help="Google Play search query; may be repeated.")
@click.option("--category", "category_ids", multiple=True, help="Exact Play category ID; repeatable.")
@click.option("--limit", type=click.IntRange(min=1), default=15000, show_default=True,
              help="Maximum number of distinct Google Play package IDs to catalogue.")
@click.option("--per-category", type=click.IntRange(min=1), default=200, show_default=True,
              help="Maximum top-free chart entries collected per category.")
@click.option("--per-query", type=click.IntRange(min=1), default=516, show_default=True,
              help="Maximum search results collected per query.")
@click.option("--packages-file", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="UTF-8 package IDs; alone, skips broad chart/search discovery.")
def discover(
    queries: tuple[str, ...],
    category_ids: tuple[str, ...],
    limit: int,
    per_category: int,
    per_query: int,
    packages_file: Path | None,
) -> None:
    """Discover app package IDs from Google Play categories, charts, and searches."""
    config = _load_config()
    logger = setup_logging(config)
    source = GooglePlaySource(
        retry_backoff_seconds=float(config.get("sources.google_play.retry_backoff_seconds", 1)),
        auth_mode=_source_auth_mode(config),
        progress=click.echo,
    )
    click.echo(BANNER)
    click.echo("Discovering applications from Google Play Store...")
    catalog = _catalog_path(config)
    apps = []
    existing_channels: dict[str, tuple[str, str]] = {}

    def persist_batch(
        batch_apps: list[PlayApp],
        batch_channels: dict[str, str] | None = None,
    ) -> None:
        # Crash-safe discovery: merge what exists with every completed channel
        # so a rate-limit abort at category 45 of 60 keeps the first 44.
        # First-seen channel wins (provenance stability across reruns).
        now = utc_now()
        for app in batch_apps:
            existing.setdefault(app.package_id, app)
            if app.package_id not in existing_channels and batch_channels:
                existing_channels[app.package_id] = (
                    batch_channels.get(app.package_id, ""), now
                )
        _write_catalog(catalog, list(existing.values()), existing_channels)

    existing: dict[str, PlayApp] = {}
    if catalog.is_file() and not catalog.is_symlink():
        for app in _read_catalog(catalog):
            existing[app.package_id] = app
        existing_channels.update(_read_catalog_channels(catalog))
    try:
        package_ids = []
        if packages_file:
            for raw in packages_file.read_text(encoding="utf-8").splitlines():
                package_id = raw.strip()
                if not package_id or package_id.startswith("#"):
                    continue
                if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                    raise click.ClickException(f"Invalid Android package ID in {packages_file}: {package_id!r}")
                package_ids.append(package_id)

        if packages_file and not queries and not category_ids:
            apps, session_channels = [], {}
        else:
            apps, session_channels = source.discover(
                queries=queries,
                category_ids=category_ids or None,
                per_category_limit=per_category,
                per_query_limit=per_query,
                total_limit=limit,
                on_batch=persist_batch,
            )
        if packages_file:
            session_packages = {app.package_id for app in apps}
            packages_note = f"packages-file:{packages_file.name}"
            for package_id in package_ids:
                if package_id in session_packages:
                    continue
                contributed = PlayApp(package_id, package_id, "", "", 0)
                apps.append(contributed)
                if package_id not in existing:
                    existing[package_id] = contributed
                existing_channels.setdefault(package_id, (packages_note, utc_now()))
                session_packages.add(package_id)
                if len(apps) >= limit:
                    break
        # Catalog semantics: the file is a rolling union of every discover
        # session that completed since it was created, so reruns after a
        # crash/rate-limit only ever add apps and never delete them.
        for app in apps:
            existing.setdefault(app.package_id, app)
        for app in apps:
            # First-seen provenance wins; pins stability for the AI handoff.
            if app.package_id not in existing_channels and session_channels:
                existing_channels[app.package_id] = (
                    session_channels.get(app.package_id, ""), utc_now()
                )
        catalog = _catalog_path(config)
        apps = list(existing.values())
        _write_catalog(catalog, apps, existing_channels)
    except (GooglePlayError, OSError, ValueError) as exc:
        logger.error("Google Play discovery failed: %s", exc)
        click.echo(f"Discovery failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("Source: GOOGLE PLAY STORE")
    click.echo(f"Distinct package IDs catalogued: {len(apps):,}")
    click.echo(f"Catalog: {catalog}")
    if not apps:
        click.echo("No Google Play applications were discovered.")
        return
    click.echo("")
    for app in apps[: min(50, len(apps))]:
        click.echo(f"{app.package_id} | {app.title} | {app.developer}")
    if len(apps) > 50:
        click.echo(f"... {len(apps) - 50:,} additional package IDs saved.")
    logger.info("Google Play discovery catalog contains %d package IDs", len(apps))


@main.command()
@click.option(
    "--apk-count",
    type=click.IntRange(min=1),
    default=None,
    show_default=False,
    help="Number of new apps to acquire (default 10; --package selects exactly one).",
)
@click.option(
    "--package",
    "package_id",
    type=str,
    default=None,
    help="Acquire this exact Google Play Android application ID.",
)
@_workspace_locked
def download(apk_count: int | None, package_id: str | None) -> None:
    """Freeze Play delivery hashes, then acquire and verify complete app bundles."""
    if package_id and apk_count not in (None, 1):
        raise click.BadParameter("--package selects one app; use --apk-count only for a multi-app batch.")
    requested_count = 1 if package_id else (apk_count or 10)
    config = _load_config()
    logger = setup_logging(config)
    context = click.get_current_context()
    context.meta["apkworkbench_run_id"] = ""
    database = WorkspaceDatabase(config.get("workspace"))
    source = GooglePlaySource(
        retry_backoff_seconds=float(config.get("sources.google_play.retry_backoff_seconds", 1)),
        auth_mode=_source_auth_mode(config),
    )
    click.echo(BANNER)
    click.echo("Preparing Google Play Store acquisition...")

    try:
        database.ensure()
        if package_id:
            try:
                catalog = _read_catalog(_catalog_path(config))
            except click.ClickException:
                catalog = []
            catalog = [app for app in catalog if app.package_id == package_id]
            if not catalog:
                catalog = [PlayApp(package_id, package_id, "", "", 0)]
        else:
            catalog = _read_catalog(_catalog_path(config))
        history = [
            row for row in database.read_download_history()
            if row.get("source") == "google_play"
        ]
        acquired_packages = {row.get("package_id", "") for row in history}
        recorded_hashes = {row.get("sha256", "").lower() for row in history}
        candidates = [app for app in catalog if app.package_id not in acquired_packages]

        # Paid, incompatible, and otherwise unavailable apps are skipped during bulk
        # selection. Authentication and API errors remain fatal rather than being hidden.
        plans = []
        unavailable = 0
        for app in candidates:
            if len(plans) >= requested_count:
                break
            click.echo(f"[metadata {len(plans) + unavailable + 1}] {app.package_id}")
            try:
                plan = source.inspect(app.package_id)
            except GooglePlayUnavailableError as exc:
                if package_id:
                    raise
                unavailable += 1
                click.echo(f"  SKIPPED (not downloadable from this Play device): {exc}")
                continue
            plans.append(plan)

        shortfall = max(0, requested_count - len(plans))
        if not plans:
            click.echo("No downloadable, new Google Play applications were selected.")
            raise click.exceptions.Exit(2 if shortfall else 0)
        click.echo(f"Previously acquired Google Play packages: {len(acquired_packages):,}")
        click.echo(f"Downloadable packages selected: {len(plans):,}")
        click.echo(f"Unavailable packages skipped: {unavailable:,}")
        if shortfall:
            click.echo(f"SHORTFALL: requested {apk_count}, found {len(plans)}; short by {shortfall}.")

        # Freeze the Play delivery metadata and expected APK hashes before the first download.
        run_id = str(uuid.uuid4())
        selected_at = utc_now()
        workspace = Path(config.get("workspace")).expanduser()
        manifest_rows = []
        manifest_hashes = set(recorded_hashes)
        selected_hashes: set[str] = set()
        plan_digests: dict[str, str] = {}
        plans_with_new_apks = []
        for plan in plans:
            plan_digest = _plan_digest(plan)
            plan_digests[plan.app.package_id] = plan_digest
            new_apks = [
                item for item in plan.files
                if item.kind == "apk" and item.sha256 and item.sha256 not in manifest_hashes
            ]
            if not new_apks:
                continue
            plans_with_new_apks.append(plan)
            for item in new_apks:
                manifest_hashes.add(item.sha256)
                selected_hashes.add(item.sha256)
                manifest_rows.append({
                    "run_id": run_id,
                    "selection_order": len(manifest_rows) + 1,
                    "selected_at": selected_at,
                    "package_id": plan.app.package_id,
                    "app_name": plan.app.title,
                    "version_code": plan.app.version_code,
                    "version_name": plan.app.version_name,
                    "source": "google_play",
                    "download_url": f"google-play://{plan.app.package_id}/{plan.app.version_code}/{item.name}",
                    "sha256": item.sha256,
                    "size": item.size,
                    "signer_sha256": ";".join(plan.signer_sha256),
                    "local_path": str(
                        workspace / "downloads" /
                        f"{plan.app.package_id}-{plan.app.version_code}" / item.name
                    ),
                    "index_sha256": plan_digest,
                })
        if not manifest_rows:
            click.echo("All APK components for the selected packages were already acquired from Google Play.")
            raise click.exceptions.Exit(0)
        plans = plans_with_new_apks
        shortfall = max(0, requested_count - len(plans))
        manifest_path = database.write_manifest(run_id, manifest_rows)
        context.meta["apkworkbench_run_id"] = run_id
        # Provenance for the AI handoff: per-package channels recorded at
        # discovery time + workspace-relative pointers to run-scoped records
        # that will exist after verification/reconciliation.
        catalog_channels = _read_catalog_channels(_catalog_path(config)) \
            if _catalog_path(config).is_file() and not _catalog_path(config).is_symlink() else {}
        provenance_by_package = {}
        for plan in plans:
            channel, channel_time = catalog_channels.get(
                plan.app.package_id,
                (f"direct:{plan.app.package_id}", selected_at),
            )
            provenance_by_package[plan.app.package_id] = {
                "discovered_via": channel,
                "discovered_at": channel_time,
                "selected_at": selected_at,
                "run_id": run_id,
                "run_manifest": f"database/run_manifests/run_{run_id}.csv",
                "phase_one_verification_report":
                    f"reports/phase_one_verification_{run_id}.json",
                "pipeline_version": str(__version__),
            }
    except click.exceptions.Exit:
        raise
    except (DatabaseError, GooglePlayError, OSError, ValueError, TypeError) as exc:
        logger.error("Google Play acquisition setup failed: %s", exc)
        click.echo(f"Download setup failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("Source: GOOGLE PLAY STORE")
    click.echo(f"Run ID: {run_id}")
    click.echo(f"Frozen manifest: {manifest_path}")
    click.echo("Play delivery metadata and expected hashes captured before downloads.")

    successes = 0
    failures = 0
    for index, plan in enumerate(plans, start=1):
        click.echo(f"[{index}/{len(plans)}] {plan.app.package_id} versionCode={plan.app.version_code}")
        try:
            bundle = source.download(
                plan,
                workspace=workspace,
                run_id=run_id,
                provenance=provenance_by_package.get(plan.app.package_id),
            )
            for apk_path in bundle.apk_files:
                digest = _file_sha256(apk_path)
                try:
                    file_info = next(item for item in plan.files if item.name == apk_path.name)
                except StopIteration as exc:
                    raise GooglePlayError(
                        "Bundle file {name!r} has no matching download-plan entry for "
                        f"{plan.app.package_id}; refusing to record an unverified APK."
                        .format(name=apk_path.name)
                    ) from exc
                if digest != file_info.sha256:
                    raise GooglePlayError(f"Local SHA-256 mismatch after Play verification: {apk_path.name}")
                if digest not in selected_hashes or digest in recorded_hashes:
                    continue
                database.append_history({
                    "sha256": digest,
                    "package_id": plan.app.package_id,
                    "app_name": plan.app.title,
                    "version_code": plan.app.version_code,
                    "version_name": plan.app.version_name,
                    "source": "google_play",
                    "download_url": f"google-play://{plan.app.package_id}/{plan.app.version_code}/{apk_path.name}",
                    "local_path": str(apk_path),
                    "size": apk_path.stat().st_size,
                    "run_id": run_id,
                    "downloaded_at": utc_now(),
                    "index_sha256": plan_digests[plan.app.package_id],
                })
                recorded_hashes.add(digest)
                database.append_attempt({
                    "timestamp": utc_now(),
                    "run_id": run_id,
                    "sha256": digest,
                    "package_id": plan.app.package_id,
                    "download_url": f"google-play://{plan.app.package_id}/{plan.app.version_code}/{apk_path.name}",
                    "status": "success",
                    "bytes_received": apk_path.stat().st_size,
                    "error": "",
                })
                successes += 1
            click.echo(f"  Verified APK components: {len(bundle.apk_files)}")
            click.echo(f"  Preserved OBB components: {len(bundle.obb_files)}")
            click.echo(f"  Bundle metadata: {bundle.manifest_path}")
        except DatabaseError as exc:
            logger.critical("Workspace persistence failed for %s: %s", plan.app.package_id, exc)
            click.echo(f"  FATAL WORKSPACE DATABASE ERROR: {exc}", err=True)
            raise click.exceptions.Exit(1) from exc
        except (GooglePlayError, OSError, StopIteration, ValueError) as exc:
            failures += 1
            logger.error("Google Play download failed for %s: %s", plan.app.package_id, exc)
            click.echo(f"  FAILED: {exc}", err=True)
            for item in plan.files:
                if item.kind == "apk" and item.sha256 in selected_hashes:
                    try:
                        database.append_attempt({
                            "timestamp": utc_now(),
                            "run_id": run_id,
                            "sha256": item.sha256,
                            "package_id": plan.app.package_id,
                            "download_url": f"google-play://{plan.app.package_id}/{plan.app.version_code}/{item.name}",
                            "status": "failed",
                            "bytes_received": 0,
                            "error": str(exc)[:1000],
                        })
                    except DatabaseError:
                        logger.exception("Could not persist failed acquisition attempt")

    click.echo("")
    click.echo("GOOGLE PLAY ACQUISITION SUMMARY")
    click.echo(f"  Applications requested: {requested_count}")
    click.echo(f"  Applications selected: {len(plans)}")
    click.echo(f"  APK components downloaded and recorded: {successes}")
    click.echo(f"  Applications failed: {failures}")
    click.echo(f"  Manifest: {manifest_path}")
    if failures:
        raise click.exceptions.Exit(1)
    if shortfall:
        raise click.exceptions.Exit(2)


@main.command("verify-downloads")
@click.option(
    "--run-id",
    required=True,
    type=str,
    help="Verify every APK/OBB file in this immutable Google Play acquisition run.",
)
@_workspace_locked
def verify_downloads(run_id: str) -> None:
    """Independently verify downloaded component files and their Play hashes."""
    config = _load_config()
    click.echo(BANNER)
    click.echo(f"Verifying Google Play acquisition run {run_id}...")
    try:
        summary = verify_google_play_run(config.get("workspace"), run_id, progress=click.echo)
    except (AcquisitionVerificationError, DatabaseError, OSError, ValueError) as exc:
        click.echo(f"Acquisition verification failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("DOWNLOAD VERIFICATION")
    click.echo(f"  Status: {summary['status'].upper()}")
    click.echo(f"  Verified bundles: {summary['verified_bundles']}")
    click.echo(f"  APK components: {summary['apk_components']}")
    click.echo(f"  OBB components: {summary['obb_components']}")
    click.echo(f"  Total bytes on disk: {summary['total_bytes']:,}")
    click.echo(f"  Verification report: {summary['report_path']}")
    for bundle in summary["bundles"]:
        click.echo(
            f"  {bundle['package_id']} v{bundle['version_code']}: "
            f"{bundle['apk_components']} APK / {bundle['obb_components']} OBB "
            f"| {bundle['directory']}"
        )


@main.command()
@click.argument(
    "folder",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def verify_workspace(folder: Path) -> None:
    """Recompute SHA-256 hashes for a frozen workspace bundle.

    Reads hashes.sha256 from the bundle root and recomputes SHA-256 for
    every file listed.  Exits non-zero on any mismatch, missing file, or
    extra file.  NEVER writes into the folder being verified.
    """
    config = _load_config()
    workspace = config.get("workspace")
    click.echo(BANNER)
    click.echo(f"Verifying workspace: {folder}")
    database = WorkspaceDatabase(workspace)
    try:
        result = database.verify_workspace(folder)
    except (DatabaseError, OSError, ValueError) as exc:
        click.echo(f"Workspace verification failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("VERIFY-WORKSPACE")
    click.echo(f"  Status: {result['status'].upper()}")
    if result.get("hash_file"):
        click.echo(f"  Hash file: {result['hash_file']}")
    if result.get("reason"):
        click.echo(f"  Reason: {result['reason']}")
    click.echo(f"  Mismatches: {len(result['mismatches'])}")
    for m in result["mismatches"]:
        click.echo(f"    - {m['rel_path']}: {m['reason']}")
    click.echo(f"  Missing: {len(result['missing'])}")
    for m in result["missing"]:
        click.echo(f"    - {m}")
    click.echo(f"  Extra: {len(result['extra'])}")
    for m in result["extra"]:
        click.echo(f"    - {m}")
    click.echo(f"  Writable evidence: {len(result['writable'])}")
    for item in result["writable"]:
        click.echo(f"    - {item['kind']}: {item['path']}")

    if result["status"] != "ok":
        raise click.exceptions.Exit(1)


@main.command()
@click.option(
    "--limit",
    type=click.IntRange(min=0),
    default=0,
    show_default=True,
    help="Maximum number of APKs to process; 0 processes all eligible downloads.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Re-run Apktool even when usable decoded output already exists.",
)
@click.option(
    "--run-id",
    type=str,
    default=None,
    help="Restrict processing to artifacts in this frozen download manifest.",
)
@_workspace_locked
def decompile(limit: int, force: bool, run_id: str | None) -> None:
    """Run Apktool against verified acquired APKs."""
    config = _load_config()
    logger = setup_logging(config)
    database = WorkspaceDatabase(config.get("workspace"))
    runner = DecompilationRunner(
        database,
        workspace=config.get("workspace"),
        apktool_executable=str(config.get("tools.apktool", "apktool")),
        timeout_seconds=int(config.get("decompilation.timeout_seconds", 3600)),
        logger=logger,
        progress=click.echo,
    )
    click.echo(BANNER)
    click.echo("Starting Apktool decoding; each APK is SHA-256 checked first.")
    try:
        summary = runner.run(limit=limit or None, force=force, run_id=run_id)
    except (DatabaseError, OSError, ValueError) as exc:
        logger.error("Decompilation run failed: %s", exc)
        click.echo(f"Decompilation failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("DECOMPILATION SUMMARY")
    if run_id:
        click.echo(f"  Run ID: {run_id}")
    click.echo(f"  Examined: {summary.examined}")
    click.echo(f"  Completed: {summary.completed}")
    click.echo(f"  Failed: {summary.failed}")
    click.echo(f"  Partial output saved: {summary.partial}")
    click.echo(f"  Already complete / skipped: {summary.skipped}")
    if summary.failed:
        raise click.exceptions.Exit(1)


@main.command()
@click.option(
    "--force",
    is_flag=True,
    help="Re-run surface analysis even when prior static-analysis output exists.",
)
@click.option(
    "--run-id",
    type=str,
    default=None,
    help="Restrict static surface analysis to artifacts in this frozen download manifest.",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Override the configured workspace directory.",
)
@_workspace_locked
def surface(force: bool, run_id: str | None, workspace: Path | None) -> None:
    """Run static APK surface analysis against Apktool-decoded output."""
    config = _load_config()
    logger = setup_logging(config)
    target_workspace = str(workspace) if workspace is not None else config.get("workspace")
    database = WorkspaceDatabase(target_workspace)
    dex_timeout = int(config.get("analysis.androguard_timeout_seconds", 1800))
    click.echo(BANNER)
    click.echo("Starting static APK surface analysis.")
    try:
        summary = run_static_surface_analysis(
            database,
            target_workspace,
            run_id=run_id,
            force=force,
            dex_timeout_seconds=dex_timeout,
            progress=click.echo,
        )
    except (DatabaseError, OSError, ValueError, RuntimeError) as exc:
        logger.error("Static surface analysis failed: %s", exc)
        click.echo(f"Static surface analysis failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("SURFACE ANALYSIS SUMMARY")
    if run_id:
        click.echo(f"  Run ID: {run_id}")
    click.echo(f"  Eligible: {summary.get('eligible', 0)}")
    click.echo(f"  Completed: {summary['completed']}")
    click.echo(f"  Partial: {summary['partial']}")
    click.echo(f"  Failed: {summary['failed']}")
    click.echo(f"  Skipped: {summary['skipped']}")
    click.echo(f"  Static indicators: {summary['finding_count']}")
    if summary["failed"]:
        raise click.exceptions.Exit(1)


@main.command()
@click.option(
    "--limit",
    type=click.IntRange(min=0),
    default=0,
    show_default=True,
    help="Maximum number of Apktool-decoded APKs to scan; 0 scans all eligible downloads.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Re-scan APKs whose previous TruffleHog scan succeeded.",
)
@click.option(
    "--run-id",
    type=str,
    default=None,
    help="Restrict analysis to artifacts in this frozen download manifest.",
)
@_workspace_locked
def analyze(limit: int, force: bool, run_id: str | None) -> None:
    """Scan Apktool-decoded output with TruffleHog and retain all findings."""
    config = _load_config()
    logger = setup_logging(config)
    database = WorkspaceDatabase(config.get("workspace"))
    scanner = TruffleHogScanner(
        database,
        workspace=config.get("workspace"),
        executable=str(config.get("tools.trufflehog", "trufflehog")),
        timeout_seconds=int(config.get("analysis.timeout_seconds", 7200)),
        max_output_bytes=int(config.get("analysis.max_output_bytes", 512 * 1024 * 1024)),
        logger=logger,
        progress=click.echo,
    )
    click.echo(BANNER)
    click.echo("Starting TruffleHog analysis with full-result selection (--results=all).")
    try:
        summary = scanner.run(limit=limit or None, force=force, run_id=run_id)
    except (AnalysisError, DatabaseError, OSError, ValueError) as exc:
        logger.error("Static analysis failed: %s", exc)
        click.echo(f"Analysis failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    try:
        link_summary = refresh_secret_links(
            database, config.get("workspace"), run_id=run_id
        )
    except (DatabaseError, OSError, ValueError, RuntimeError) as exc:
        logger.error("Secret-link refresh failed: %s", exc)
        click.echo(f"Secret-link refresh failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("TRUFFLEHOG FINDING COUNTS BY TYPE")
    if not summary.finding_records:
        click.echo("  No findings were emitted by the scans performed in this run.")
    else:
        counts_by_type: dict[str, dict[str, int]] = {}
        for record in summary.finding_records:
            finding = record.get("finding") or {}
            detector = str(finding.get("DetectorName") or "unknown")
            bucket = counts_by_type.setdefault(
                detector, {"total": 0, "verified": 0, "unverified": 0}
            )
            bucket["total"] += 1
            if finding.get("Verified") is True:
                bucket["verified"] += 1
            else:
                bucket["unverified"] += 1
        for detector, bucket in sorted(
            counts_by_type.items(), key=lambda item: (-item[1]["total"], item[0])
        ):
            click.echo(
                f"  {detector}: {bucket['total']} "
                f"(verified: {bucket['verified']}, unverified: {bucket['unverified']})"
            )

    click.echo("\nANALYSIS SUMMARY")
    if run_id:
        click.echo(f"  Run ID: {run_id}")
    click.echo(f"  APKs scanned: {summary.scanned}")
    click.echo(f"  Candidate findings: {summary.findings}")
    click.echo(f"  Failed scans: {summary.failed}")
    click.echo(f"  Skipped / not decompiled: {summary.skipped}")
    click.echo(
        f"  Secret links refreshed: {link_summary['updated']}; "
        f"failed: {link_summary['failed']}; "
        f"missing surface output: {link_summary['missing_surface']}; "
        f"already frozen: {link_summary['frozen']}"
    )
    if link_summary["frozen"]:
        click.echo(
            "  Frozen bundles were left unchanged; re-analysis must use an "
            "unfrozen evidence workspace.",
            err=True,
        )
    click.echo(f"  Complete-finding aggregate: {Path(config.get('workspace')) / 'reports/findings.csv'}")
    if summary.failed or link_summary["failed"] or link_summary["frozen"]:
        raise click.exceptions.Exit(1)


@main.command()
@click.option("--run-id", type=str, default=None, help="Also generate a consolidated report for this frozen run.")
@_workspace_locked
def report(run_id: str | None) -> None:
    """Generate per-APK reports and, when scoped, one complete run evidence package."""

    config = _load_config()
    logger = setup_logging(config)
    generator = ReportGenerator(
        WorkspaceDatabase(config.get("workspace")),
        workspace=config.get("workspace"),
    )
    click.echo(BANNER)
    try:
        summary = generator.run()
        final_report = (
            generate_final_run_report(WorkspaceDatabase(config.get("workspace")), config.get("workspace"), run_id)
            if run_id else None
        )
    except (ReportingError, FinalRunReportError, DatabaseError, OSError, ValueError) as exc:
        logger.error("Report generation failed: %s", exc)
        click.echo(f"Report generation failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("REPORT SUMMARY")
    click.echo(f"  Reports generated: {summary.generated}")
    click.echo(f"  APKs with findings: {summary.with_findings}")
    click.echo(f"  Total candidate findings: {summary.total_findings}")
    click.echo(f"  Output directory: {Path(config.get('workspace')) / 'reports'}")
    if final_report:
        click.echo("CONSOLIDATED FINAL RUN REPORT")
        click.echo(f"  JSON: {final_report['json_path']}")
        click.echo(f"  HTML: {final_report['html_path']}")
        click.echo(f"  API endpoint candidates: {final_report['api_endpoint_count']}")
        click.echo(f"  API route candidates: {final_report['api_route_count']}")
        click.echo(f"  Smali API call sites: {final_report['api_call_site_count']}")
        click.echo(f"  Androguard external method references: {final_report['androguard_external_method_count']}")
        click.echo(f"  DEX API/config string candidates: {final_report['androguard_api_string_count']}")
        click.echo(f"  Permission-to-API usage groups: {final_report['permission_api_usage_count']}")
        click.echo(f"  Client rate-limit/retry clues: {final_report['rate_limit_indicator_count']}")
        click.echo(f"  Static indicators: {final_report['static_findings']}")
        click.echo(f"  Verified TruffleHog findings: {final_report['verified_findings']}")


@main.command()
@_workspace_locked
def status() -> None:
    """Summarize acquisition, decompilation, and scan state."""
    config = _load_config()
    database = WorkspaceDatabase(config.get("workspace"))
    try:
        history = database.read_download_history()
        acquired_hashes = {row.get("sha256", "").lower() for row in history}
        processing = database.read_processing_status()
        processing = {digest: row for digest, row in processing.items() if digest in acquired_hashes}
    except DatabaseError as exc:
        click.echo(f"Status unavailable: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    total = len(history)
    apktool_ok = sum(1 for row in processing.values() if row.get("apktool_status") == "success")
    scan_ok = sum(1 for row in processing.values() if row.get("scan_status") == "success")
    decompile_failed = sum(1 for row in processing.values() if row.get("apktool_status") == "failed")
    scan_failed = sum(1 for row in processing.values() if row.get("scan_status") == "failed")
    click.echo(BANNER)
    click.echo("WORKSPACE STATUS")
    click.echo(f"  Unique acquired APK binaries: {total}")
    click.echo(f"  Apktool decoded: {apktool_ok}")
    click.echo(f"  TruffleHog scans complete: {scan_ok}")
    click.echo(f"  Apktool failures: {decompile_failed}")
    click.echo(f"  Scan failures: {scan_failed}")
    click.echo(f"  Workspace: {config.get('workspace')}")



@main.command()
@click.option(
    "--apk-count",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of new Google Play applications to acquire.",
)
@click.option(
    "--package",
    "package_id",
    type=str,
    default=None,
    help="Restrict the acquisition to this exact Android package ID.",
)
@click.option(
    "--local-apk",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Run the self-contained pipeline on a local APK file or bundle directory.",
)
@click.option("--force-decompile", is_flag=True, help="Re-run completed decompilations.")
@click.option("--force-surface", is_flag=True, help="Re-run completed static surface analysis.")
@click.option("--force-analyze", is_flag=True, help="Re-run successful TruffleHog scans.")
def run(
    apk_count: int,
    package_id: str | None,
    local_apk: Path | None,
    force_decompile: bool,
    force_surface: bool,
    force_analyze: bool,
) -> None:
    """Acquire from the saved discovery catalog (or one exact package), then process the batch."""
    if local_apk is not None:
        config = _load_config()
        logger = setup_logging(config)
        click.echo(BANNER)
        click.echo(f"SELF-CONTAINED LOCAL APK PIPELINE: {local_apk}")
        try:
            result = run_local_apk_self_contained(
                local_apk,
                config.get("workspace"),
                config=config,
                package_id=package_id,
                progress=click.echo,
                logger=logger,
            )
        except (DatabaseError, OSError, ValueError, RuntimeError) as exc:
            logger.error("Self-contained local APK run failed: %s", exc)
            click.echo(f"Local APK run failed: {exc}", err=True)
            raise click.exceptions.Exit(1) from exc
        click.echo("\nSELF-CONTAINED RUN COMPLETE")
        click.echo(f"  Run ID: {result['run_id']}")
        click.echo(f"  Package: {result['package_id']} v{result['version_code']}")
        click.echo(f"  Run folder: {result['run_dir']}")
        click.echo(f"  README: {result['readme_path']}")
        click.echo(f"  Index: {result['index_path']}")
        click.echo(f"  Status: {result['status']}")
        if result.get("status") not in {"complete", "complete_with_warnings"}:
            raise click.exceptions.Exit(1)
        return

    workspace = _load_config().get("workspace")
    database = WorkspaceDatabase(workspace)
    with database._write_lock():
        _run_play_pipeline(
            apk_count=apk_count,
            package_id=package_id,
            force_decompile=force_decompile,
            force_surface=force_surface,
            force_analyze=force_analyze,
        )


def _run_play_pipeline(
    *,
    apk_count: int,
    package_id: str | None,
    force_decompile: bool,
    force_surface: bool,
    force_analyze: bool,
) -> None:
    context = click.get_current_context()
    context.meta["apkworkbench_run_id"] = ""
    stages_with_issues: list[str] = []
    reconciliation: dict | None = None
    reconciliation_error = ""
    click.echo(BANNER)
    click.echo("FULL SEQUENTIAL PIPELINE")

    for stage_name, command, kwargs in (
        ("download", download, {"apk_count": 1 if package_id else apk_count, "package_id": package_id}),
        ("decompile", decompile, {"limit": 0, "force": force_decompile}),
        ("surface", None, {}),
        ("analyze", analyze, {"limit": 0, "force": force_analyze}),
        ("report", report, {}),
    ):
        click.echo(f"\n=== {stage_name.upper()} ===")
        if stage_name in {"decompile", "surface", "analyze"}:
            run_id = context.meta.get("apkworkbench_run_id")
            if not run_id:
                click.echo(
                    f"Stopping pipeline: no immutable download manifest was published; "
                    f"{stage_name} will not run."
                )
                stages_with_issues.append(f"{stage_name}_missing_run_manifest")
                break
            kwargs["run_id"] = run_id
        if stage_name == "analyze":
            usable_outputs = _count_usable_apktool_outputs(_load_config().get("workspace"), run_id)
            if usable_outputs == 0:
                click.echo(
                    "No usable Apktool output was saved for this run. TruffleHog will be skipped; "
                    "reporting and reconciliation will continue."
                )
                stages_with_issues.append("no_usable_apktool_output")
                continue
            click.echo(
                f"Starting TruffleHog for {usable_outputs} APK(s) with saved Apktool output "
                "(complete or partial)."
            )
        if stage_name == "surface":
            click.echo("\n=== STATIC APK SURFACE ANALYSIS ===")
            click.echo("Cataloguing manifest, components, permissions, API endpoints/routes, network, code, dependencies and native libraries.")
            try:
                surface_summary = run_static_surface_analysis(
                    WorkspaceDatabase(_load_config().get("workspace")),
                    _load_config().get("workspace"),
                    run_id=run_id,
                    force=force_surface,
                    dex_timeout_seconds=int(_load_config().get("analysis.androguard_timeout_seconds", 1800)),
                    progress=click.echo,
                )
            except (DatabaseError, OSError, ValueError, RuntimeError) as exc:
                click.echo(f"Static surface analysis failed: {exc}", err=True)
                stages_with_issues.append("surface")
            else:
                click.echo(
                    f"Static surface analysis: {surface_summary['completed']} completed, "
                    f"{surface_summary['partial']} partial, {surface_summary['failed']} failed, "
                    f"{surface_summary['skipped']} skipped; "
                    f"{surface_summary['finding_count']} indicators."
                )
                if surface_summary["failed"]:
                    stages_with_issues.append("surface")
            continue

        if stage_name == "report":
            kwargs["run_id"] = context.meta.get("apkworkbench_run_id")
        try:
            context.invoke(command, **kwargs)
        except click.exceptions.Exit as exc:
            if exc.exit_code:
                stages_with_issues.append(stage_name)
                click.echo(f"Stage {stage_name} ended with exit code {exc.exit_code}.")
                if stage_name == "decompile":
                    usable_outputs = _count_usable_apktool_outputs(
                        _load_config().get("workspace"), context.meta.get("apkworkbench_run_id", "")
                    )
                    if usable_outputs:
                        click.echo(
                            f"{usable_outputs} APK(s) have saved usable Apktool output. "
                            "Continuing to TruffleHog for those artifacts; failed APKs remain recorded."
                        )
                    else:
                        click.echo(
                            "No usable Apktool output exists. TruffleHog will be skipped; "
                            "reporting and reconciliation will continue."
                        )
                    continue
                if stage_name == "analyze":
                    click.echo(
                        "TruffleHog completed its per-APK pass with failures. "
                        "Continuing to reports and reconciliation for saved results."
                    )
                    continue
                if stage_name == "download":
                    click.echo("Download stage failed. Stopping before decompilation and analysis.")
                    break
                if stage_name == "report":
                    click.echo("Report generation failed; see the report log.")
                    break
        if stage_name == "download":
            run_id = context.meta.get("apkworkbench_run_id")
            if not run_id:
                click.echo("Stopping pipeline: download completed without publishing a run ID.")
                stages_with_issues.append("download_missing_run_id")
                break
            click.echo("\n=== DOWNLOAD VERIFICATION ===")
            try:
                verification = verify_google_play_run(_load_config().get("workspace"), run_id, progress=click.echo)
            except (AcquisitionVerificationError, DatabaseError, OSError, ValueError) as exc:
                click.echo(f"Download verification failed: {exc}", err=True)
                stages_with_issues.append("download_verification")
                click.echo(
                    "Stopping before Apktool and TruffleHog because acquisition "
                    "verification did not complete."
                )
                break
            click.echo(
                f"Verified {verification['verified_bundles']} bundle(s), "
                f"{verification['apk_components']} APK component(s), and "
                f"{verification['obb_components']} OBB component(s)."
            )
            click.echo(f"Verification report: {verification['report_path']}")
        if stage_name == "decompile":
            click.echo(
                "Apktool stage completed. Static surface analysis and TruffleHog will now run independently."
            )

    run_id = context.meta.get("apkworkbench_run_id")
    if run_id:
        try:
            reconciliation = WorkspaceDatabase(_load_config().get("workspace")).reconcile_run(run_id)
        except DatabaseError as exc:
            reconciliation_error = str(exc)
            click.echo(f"RUN RECONCILIATION FAILED: {exc}", err=True)
            stages_with_issues.append("reconciliation")
        else:
            click.echo("\nRUN RECONCILIATION")
            for outcome, count in reconciliation["counts"].items():
                click.echo(f"  {outcome}: {count}")
            total = int(reconciliation["total"])
            complete = int(reconciliation["complete"])
            click.echo(f"  Final accounting: {complete}/{total} artifacts complete.")
            if reconciliation["counts"].get("complete_with_warnings", 0):
                click.echo(
                    f"  Completed after partial Apktool output: "
                    f"{reconciliation['counts']['complete_with_warnings']} artifact(s)."
                )
            if complete != total:
                stages_with_issues.append("reconciliation")

    if run_id:
        try:
            stage_status_counts = _write_bundle_stage_statuses(
                WorkspaceDatabase(_load_config().get("workspace")),
                _load_config().get("workspace"),
                run_id,
                pipeline_issues=stages_with_issues,
            )
        except (DatabaseError, OSError, ValueError) as exc:
            stage_status_counts = {}
            click.echo(f"Per-artifact stage status write failed: {exc}", err=True)
            stages_with_issues.append("bundle_stage_status")
        if stage_status_counts.get("frozen_skipped", 0):
            click.echo(
                f"Preserved {stage_status_counts['frozen_skipped']} already-frozen "
                "bundle(s); per-artifact status files were not added."
            )
            stages_with_issues.append("bundle_stage_status_frozen")
        if stage_status_counts.get("missing", 0):
            stages_with_issues.append("bundle_stage_status_missing")

    # Freeze every fully-processed artifact bundle: handoff.json +
    # hashes.sha256 + read-only evidence so verify-workspace can prove it.
    if run_id:
        click.echo("\n=== FREEZE EVIDENCE ===")
        workspace = Path(_load_config().get("workspace")).expanduser()
        results_root = workspace / "results"
        database = WorkspaceDatabase(workspace)
        try:
            manifest = database.read_manifest(run_id)
        except DatabaseError:
            manifest = []
        frozen = 0
        freeze_issues = 0
        for selected in manifest:
            digest = selected["sha256"].lower()
            package_id = selected.get("package_id", "")
            version_code = str(selected.get("version_code", ""))
            bundle_dir = results_root / package_id / version_code / digest
            if not bundle_dir.is_dir():
                continue
            # Already frozen bundles keep their immutable manifest.
            if (bundle_dir / "hashes.sha256").is_file():
                frozen += 1
                continue
            try:
                database.freeze_evidence(bundle_dir)
                frozen += 1
                click.echo(
                    f"  Frozen: {package_id} {version_code} [{digest[:12]}]"
                )
            except (DatabaseError, OSError) as exc:
                freeze_issues += 1
                click.echo(
                    f"  Freeze failed for {package_id} {version_code}: {exc}",
                    err=True,
                )
        if freeze_issues:
            stages_with_issues.append("freeze")
        click.echo(f"  Frozen {frozen} artifact bundle(s).")
        try:
            _write_run_stage_statuses(
                database,
                workspace,
                run_id,
                reconciliation=reconciliation,
                reconciliation_error=reconciliation_error,
                frozen=frozen,
                freeze_issues=freeze_issues,
                pipeline_issues=stages_with_issues,
            )
        except (DatabaseError, OSError, ValueError) as exc:
            click.echo(f"Run-level stage status write failed: {exc}", err=True)
            stages_with_issues.append("run_stage_status")

    click.echo("\nFULL PIPELINE SUMMARY")
    if stages_with_issues:
        click.echo("Stages requiring attention: " + ", ".join(stages_with_issues))
        click.echo("Review 'apkworkbench status' and the per-artifact logs.")
        raise click.exceptions.Exit(1)
    click.echo("All pipeline stages completed and every manifest item is accounted for.")


@main.command()
@click.option("--run-id", required=True, type=str, help="Frozen acquisition run ID to reconcile.")
@_workspace_locked
def reconcile(run_id: str) -> None:
    """Report the terminal outcome of every item in a frozen acquisition manifest."""
    database = WorkspaceDatabase(_load_config().get("workspace"))
    try:
        result = database.reconcile_run(run_id)
    except DatabaseError as exc:
        click.echo(f"Reconciliation unavailable: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo(BANNER)
    click.echo(f"RUN RECONCILIATION: {run_id}")
    click.echo(f"  Manifest items: {result['total']}")
    click.echo(f"  Complete: {result['complete']}")
    for outcome, count in result["counts"].items():
        click.echo(f"  {outcome}: {count}")

    unresolved = [item for item in result["items"] if item["status"] != "complete"]
    if unresolved:
        click.echo("UNRESOLVED ITEMS")
        for item in unresolved:
            click.echo(
                f"  {item['package_id']} {item['version_code']} "
                f"[{item['sha256'][:12]}]: {item['status']}"
            )
            if item["detail"]:
                click.echo(f"    {item['detail']}")
        raise click.exceptions.Exit(1)

    click.echo("All manifest items have a complete terminal outcome.")


@main.command()
@click.option(
    "--source",
    required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to the legacy 0.2.0 workspace directory.",
)
@click.option(
    "--target",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Target single-folder home directory (default: configured workspace).",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    default=False,
    help="Copy bundles into the target layout (default is dry-run).",
)
def migrate(source: Path, target: Path | None, apply_changes: bool) -> None:
    """Copy legacy workspace bundles into self-contained run folders (non-destructive)."""
    config = _load_config()
    target_home = target if target is not None else Path(config.get("workspace")).expanduser()
    legacy_cfg = Path.home() / ".config" / "apkworkbench" / "config.yaml"
    report = migrate_legacy_workspace(
        source,
        target_home,
        dry_run=not apply_changes,
        legacy_config_path=legacy_cfg if legacy_cfg.is_file() else None,
    )
    mode_label = "APPLY" if apply_changes else "DRY-RUN"
    click.echo(BANNER)
    click.echo(f"WORKSPACE MIGRATION ({mode_label})")
    click.echo(f"  Source: {report['source']}")
    click.echo(f"  Target: {report['target']}")
    click.echo(f"  Bundles discovered: {report['bundles_discovered']}")
    click.echo(f"  Bundles migrated: {report['bundles_migrated']}")
    click.echo(f"  Dossiers found / verified: {report['dossiers_found']} / {report['dossiers_verified']}")
    click.echo(f"  Lead ledgers found / verified: {report['lead_ledgers_found']} / {report['lead_ledgers_verified']}")
    if not apply_changes:
        click.echo("  Dry-run only: no files were copied. Re-run with --apply to migrate.")


@main.command()
def version() -> None:
    """Print the installed package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
