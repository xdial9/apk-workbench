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
from apkworkbench.analysis.apk_surface import run_static_surface_analysis
from apkworkbench.core.config import Config
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


def _workspace_locked(command):
    """Hold the workspace process lock for each command and the full pipeline."""
    @wraps(command)
    def wrapped(*args, **kwargs):
        workspace = Config().get("workspace")
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


def _write_catalog(path: Path, apps: list[PlayApp]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=".google-play-discovery.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=["package_id", "title", "developer", "version_name", "version_code"]
            )
            writer.writeheader()
            for app in apps:
                writer.writerow({
                    "package_id": app.package_id,
                    "title": app.title,
                    "developer": app.developer,
                    "version_name": app.version_name,
                    "version_code": app.version_code,
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
def main() -> None:
    """Discover, acquire, decompile, analyze, and catalogue APK files."""


@main.command()
def doctor() -> None:
    """Check required and optional external dependencies."""
    config = Config()
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
              help="Optional UTF-8 file containing one Google Play package ID per line.")
def discover(
    queries: tuple[str, ...],
    category_ids: tuple[str, ...],
    limit: int,
    per_category: int,
    per_query: int,
    packages_file: Path | None,
) -> None:
    """Discover app package IDs from Google Play categories, charts, and searches."""
    config = Config()
    logger = setup_logging(config)
    source = GooglePlaySource(
        retry_backoff_seconds=float(config.get("sources.google_play.retry_backoff_seconds", 1)),
        progress=click.echo,
    )
    click.echo(BANNER)
    click.echo("Discovering applications from Google Play Store...")
    try:
        apps = source.discover(
            queries=queries,
            category_ids=category_ids or None,
            per_category_limit=per_category,
            per_query_limit=per_query,
            total_limit=limit,
        )
        if packages_file:
            existing = {app.package_id for app in apps}
            for raw in packages_file.read_text(encoding="utf-8").splitlines():
                package_id = raw.strip()
                if not package_id or package_id.startswith("#") or package_id in existing:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package_id):
                    raise click.ClickException(f"Invalid Android package ID in {packages_file}: {package_id!r}")
                apps.append(PlayApp(package_id, package_id, "", "", 0))
                existing.add(package_id)
                if len(apps) >= limit:
                    break
        catalog = _catalog_path(config)
        _write_catalog(catalog, apps)
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
    config = Config()
    logger = setup_logging(config)
    context = click.get_current_context()
    context.meta["apkworkbench_run_id"] = ""
    database = WorkspaceDatabase(config.get("workspace"))
    source = GooglePlaySource(
        retry_backoff_seconds=float(config.get("sources.google_play.retry_backoff_seconds", 1)),
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
            bundle = source.download(plan, workspace=workspace, run_id=run_id)
            for apk_path in bundle.apk_files:
                digest = _file_sha256(apk_path)
                file_info = next(item for item in plan.files if item.name == apk_path.name)
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
    config = Config()
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
    config = Config()
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
    """Scan Apktool-decoded output and retain verified findings."""
    config = Config()
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
    click.echo("Starting TruffleHog analysis with verified-result selection (--results=verified).")
    try:
        summary = scanner.run(limit=limit or None, force=force, run_id=run_id)
    except (AnalysisError, DatabaseError, OSError, ValueError) as exc:
        logger.error("Static analysis failed: %s", exc)
        click.echo(f"Analysis failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("COMPLETE ORIGINAL TRUFFLEHOG FINDINGS")
    if not summary.finding_records:
        click.echo("  No findings were emitted by the scans performed in this run.")
    for record in summary.finding_records:
        click.echo(f"\nAPK: {record['package_id']}  VERSION: {record['version_code']}  SHA256: {record['sha256']}")
        click.echo(json.dumps(record["finding"], ensure_ascii=False, indent=2))

    click.echo("\nANALYSIS SUMMARY")
    if run_id:
        click.echo(f"  Run ID: {run_id}")
    click.echo(f"  APKs scanned: {summary.scanned}")
    click.echo(f"  Candidate findings: {summary.findings}")
    click.echo(f"  Failed scans: {summary.failed}")
    click.echo(f"  Skipped / not decompiled: {summary.skipped}")
    click.echo(f"  Complete-finding aggregate: {Path(config.get('workspace')) / 'reports/findings.csv'}")
    if summary.failed:
        raise click.exceptions.Exit(1)


@main.command()
@click.option("--run-id", type=str, default=None, help="Also generate a consolidated report for this frozen run.")
@_workspace_locked
def report(run_id: str | None) -> None:
    """Generate per-APK reports and, when scoped, one complete run evidence package."""

    config = Config()
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
        click.echo(f"  Client rate-limit/retry clues: {final_report['rate_limit_indicator_count']}")
        click.echo(f"  Static indicators: {final_report['static_findings']}")
        click.echo(f"  Verified TruffleHog findings: {final_report['verified_findings']}")


@main.command()
@_workspace_locked
def status() -> None:
    """Summarize acquisition, decompilation, and scan state."""
    config = Config()
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
@click.option("--force-decompile", is_flag=True, help="Re-run completed decompilations.")
@click.option("--force-analyze", is_flag=True, help="Re-run successful TruffleHog scans.")
@_workspace_locked
def run(
    apk_count: int,
    package_id: str | None,
    force_decompile: bool,
    force_analyze: bool,
) -> None:
    """Acquire from the saved discovery catalog (or one exact package), then process the batch."""
    context = click.get_current_context()
    context.meta["apkworkbench_run_id"] = ""
    stages_with_issues: list[str] = []
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
            usable_outputs = _count_usable_apktool_outputs(Config().get("workspace"), run_id)
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
                    WorkspaceDatabase(Config().get("workspace")),
                    Config().get("workspace"),
                    run_id=run_id,
                    progress=click.echo,
                )
            except (DatabaseError, OSError, ValueError, RuntimeError) as exc:
                click.echo(f"Static surface analysis failed: {exc}", err=True)
                stages_with_issues.append("surface")
            else:
                click.echo(
                    f"Static surface analysis: {surface_summary['completed']} completed, "
                    f"{surface_summary['failed']} failed, {surface_summary['skipped']} skipped; "
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
                        Config().get("workspace"), context.meta.get("apkworkbench_run_id", "")
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
                verification = verify_google_play_run(Config().get("workspace"), run_id, progress=click.echo)
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
            reconciliation = WorkspaceDatabase(Config().get("workspace")).reconcile_run(run_id)
        except DatabaseError as exc:
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
    database = WorkspaceDatabase(Config().get("workspace"))
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
def version() -> None:
    """Print the installed package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
