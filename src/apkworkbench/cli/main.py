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
from apkworkbench.analysis.trufflehog import AnalysisError, TruffleHogScanner
from apkworkbench.core.config import Config
from apkworkbench.core.logging import setup_logging
from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase, utc_now
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.reporting.generator import ReportGenerator, ReportingError
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
    help="Re-run decompilation even when both tools already have usable output.",
)
@click.option(
    "--run-id",
    type=str,
    default=None,
    help="Restrict processing to artifacts in this frozen download manifest.",
)
@_workspace_locked
def decompile(limit: int, force: bool, run_id: str | None) -> None:
    """Run JADX and Apktool sequentially against verified acquired APKs."""
    config = Config()
    logger = setup_logging(config)
    database = WorkspaceDatabase(config.get("workspace"))
    runner = DecompilationRunner(
        database,
        workspace=config.get("workspace"),
        jadx_executable=str(config.get("tools.jadx", "jadx")),
        apktool_executable=str(config.get("tools.apktool", "apktool")),
        timeout_seconds=int(config.get("decompilation.timeout_seconds", 3600)),
        logger=logger,
    )
    click.echo(BANNER)
    click.echo("Starting sequential decompilation; each APK is SHA-256 checked first.")
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
    click.echo(f"  Completed with partial JADX output: {summary.partial}")
    click.echo(f"  Failed: {summary.failed}")
    click.echo(f"  Already complete / skipped: {summary.skipped}")
    if summary.failed:
        raise click.exceptions.Exit(1)


@main.command()
@click.option(
    "--limit",
    type=click.IntRange(min=0),
    default=0,
    show_default=True,
    help="Maximum number of fully or partially decompiled APKs to scan; 0 scans all eligible downloads.",
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
    """Scan usable full or partial decompilations locally; verification is disabled."""
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
    )
    click.echo(BANNER)
    click.echo("Starting local TruffleHog analysis with credential verification disabled.")
    try:
        summary = scanner.run(limit=limit or None, force=force, run_id=run_id)
    except (AnalysisError, DatabaseError, OSError, ValueError) as exc:
        logger.error("Static analysis failed: %s", exc)
        click.echo(f"Analysis failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("ANALYSIS SUMMARY")
    if run_id:
        click.echo(f"  Run ID: {run_id}")
    click.echo(f"  APKs scanned: {summary.scanned}")
    click.echo(f"  Candidate findings: {summary.findings}")
    click.echo(f"  Failed scans: {summary.failed}")
    click.echo(f"  Skipped / not decompiled: {summary.skipped}")
    click.echo(f"  Sanitized aggregate: {Path(config.get('workspace')) / 'reports/findings.csv'}")
    if summary.failed:
        raise click.exceptions.Exit(1)


@main.command()
@_workspace_locked
def report() -> None:
    """Generate sanitized per-APK JSON and HTML reports."""
    config = Config()
    logger = setup_logging(config)
    generator = ReportGenerator(
        WorkspaceDatabase(config.get("workspace")),
        workspace=config.get("workspace"),
    )
    click.echo(BANNER)
    try:
        summary = generator.run()
    except (ReportingError, DatabaseError, OSError, ValueError) as exc:
        logger.error("Report generation failed: %s", exc)
        click.echo(f"Report generation failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("REPORT SUMMARY")
    click.echo(f"  Reports generated: {summary.generated}")
    click.echo(f"  APKs with findings: {summary.with_findings}")
    click.echo(f"  Total candidate findings: {summary.total_findings}")
    click.echo(f"  Output directory: {Path(config.get('workspace')) / 'reports'}")


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
    jadx_ok = sum(1 for row in processing.values() if row.get("jadx_status") == "success")
    apktool_ok = sum(1 for row in processing.values() if row.get("apktool_status") == "success")
    scan_ok = sum(1 for row in processing.values() if row.get("scan_status") == "success")
    decompile_failed = sum(
        1 for row in processing.values()
        if row.get("jadx_status") == "failed" or row.get("apktool_status") == "failed"
    )
    scan_failed = sum(1 for row in processing.values() if row.get("scan_status") == "failed")
    click.echo(BANNER)
    click.echo("WORKSPACE STATUS")
    click.echo(f"  Unique acquired APK binaries: {total}")
    click.echo(f"  JADX complete: {jadx_ok}")
    click.echo(f"  Apktool complete: {apktool_ok}")
    click.echo(f"  Fully decompiled: {sum(1 for row in processing.values() if row.get('jadx_status') == 'success' and row.get('apktool_status') == 'success')}")
    click.echo(f"  TruffleHog scans complete: {scan_ok}")
    click.echo(f"  Decompilation failures: {decompile_failed}")
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
        ("analyze", analyze, {"limit": 0, "force": force_analyze}),
        ("report", report, {}),
    ):
        click.echo(f"\n=== {stage_name.upper()} ===")
        if stage_name in {"decompile", "analyze"}:
            run_id = context.meta.get("apkworkbench_run_id")
            if not run_id:
                click.echo(
                    f"Skipping {stage_name}: this pipeline invocation did not publish "
                    "a download manifest."
                )
                continue
            kwargs["run_id"] = run_id
        try:
            context.invoke(command, **kwargs)
        except click.exceptions.Exit as exc:
            if exc.exit_code:
                stages_with_issues.append(stage_name)
                click.echo(
                    f"Stage {stage_name} ended with exit code {exc.exit_code}; "
                    "continuing with eligible artifacts from this run."
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
