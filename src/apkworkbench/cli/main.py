"""APK Workbench command-line entry point."""
import hashlib
import uuid
from functools import wraps
from pathlib import Path

import click

from apkworkbench import __version__
from apkworkbench.acquisition.downloader import ArtifactDownloader, DownloadError
from apkworkbench.acquisition.selector import select_new_artifacts
from apkworkbench.analysis.trufflehog import AnalysisError, TruffleHogScanner
from apkworkbench.core.config import Config
from apkworkbench.core.logging import setup_logging
from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase, utc_now
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.reporting.generator import ReportGenerator, ReportingError
from apkworkbench.dependencies.detector import DependencyDetector
from apkworkbench.security.gpg_verifier import GpgVerifier
from apkworkbench.sources.fdroid import FdroidArtifact, FdroidIndexError, FdroidIndexParser
from apkworkbench.sources.fdroid_repository import (
    FdroidRepositoryClient,
    FdroidRepositoryError,
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


def _load_fdroid_artifacts(config: Config, *, force_refresh: bool = False):
    """Retrieve or reuse a re-verified F-Droid index, then parse authenticated bytes."""
    source = config.get("sources.fdroid", {})
    repository_url = str(source.get("repository_url", "https://f-droid.org/repo"))
    verifier = GpgVerifier(config)
    client = FdroidRepositoryClient(
        verifier,
        repository_url=repository_url,
        key_url=str(source["key_url"]),
        signer_fingerprint=str(source["signer_fingerprint"]),
        timeout_seconds=int(source.get("timeout_seconds", 30)),
        max_index_bytes=int(source.get("max_index_bytes", 128 * 1024 * 1024)),
        max_signature_bytes=int(source.get("max_signature_bytes", 1024 * 1024)),
        max_key_bytes=int(source.get("max_key_bytes", 2 * 1024 * 1024)),
        progress_callback=click.echo,
    )
    state_dir = config.get("state_dir")
    cache_dir = Path(state_dir).expanduser() / "fdroid-cache" if state_dir else None
    index_data = client.fetch_verified_index(
        cache_dir=cache_dir,
        cache_ttl_seconds=int(source.get("cache_ttl_seconds", 21600)),
        force_refresh=force_refresh,
    )
    artifacts = FdroidIndexParser(repository_url).parse(index_data)
    return client, index_data, artifacts


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
@click.option(
    "--package",
    "package_id",
    type=str,
    default=None,
    help="Show only this exact Android application ID.",
)
@click.option(
    "--limit",
    type=click.IntRange(min=0),
    default=20,
    show_default=True,
    help="Maximum number of latest-per-package records to display; 0 displays none.",
)
@click.option(
    "--refresh-index",
    is_flag=True,
    help="Ignore the local index cache and retrieve a fresh signed index.",
)
def discover(package_id: str | None, limit: int, refresh_index: bool) -> None:
    """Fetch, authenticate, and summarize the official F-Droid index-v2."""
    config = Config()
    logger = setup_logging(config)
    click.echo(BANNER)
    click.echo("Retrieving the F-Droid repository index and detached signature...")

    try:
        client, index_data, artifacts = _load_fdroid_artifacts(config, force_refresh=refresh_index)
    except (FdroidRepositoryError, FdroidIndexError, KeyError, TypeError, ValueError) as exc:
        logger.error("F-Droid discovery failed: %s", exc)
        click.echo(f"Discovery failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    latest_by_package: dict[str, FdroidArtifact] = {}
    for artifact in artifacts:
        current = latest_by_package.get(artifact.package_id)
        if current is None or artifact.version_code > current.version_code:
            latest_by_package[artifact.package_id] = artifact

    latest = list(latest_by_package.values())
    if package_id:
        latest = [item for item in latest if item.package_id == package_id]

    latest.sort(key=lambda item: item.package_id)
    unique_hashes = len({item.sha256 for item in artifacts})
    click.echo("Index signature: VERIFIED")
    click.echo(f"Signer primary fingerprint: {client.signer_fingerprint}")
    click.echo(f"Index SHA-256: {hashlib.sha256(index_data).hexdigest()}")
    click.echo(f"Indexed APK version records: {len(artifacts):,}")
    click.echo(f"Distinct binary SHA-256 values: {unique_hashes:,}")
    click.echo(f"Packages with indexed versions: {len(latest_by_package):,}")
    if package_id:
        click.echo(f"Exact package filter: {package_id}")
    click.echo("")
    if not latest:
        click.echo("No matching packages found.")
        return

    click.echo("LATEST INDEXED VERSIONS")
    for artifact in latest[:limit]:
        version = artifact.version_name or "(unnamed)"
        click.echo(
            f"{artifact.package_id} | {version} | code {artifact.version_code} "
            f"| {artifact.size:,} bytes | SHA-256 {artifact.sha256}"
        )
    if len(latest) > limit:
        click.echo(f"... {len(latest) - limit:,} additional package records not displayed.")
    logger.info(
        "Authenticated F-Droid index: %d version records, %d unique binaries",
        len(artifacts),
        unique_hashes,
    )


@main.command()
@click.option(
    "--apk-count",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of new, unique APK binaries to acquire.",
)
@click.option(
    "--package",
    "package_id",
    type=str,
    default=None,
    help="Restrict selection to this exact Android application ID.",
)
@click.option(
    "--refresh-index",
    is_flag=True,
    help="Ignore the local index cache and retrieve a fresh signed index.",
)
@_workspace_locked
def download(apk_count: int, package_id: str | None, refresh_index: bool) -> None:
    """Select new APK binaries, freeze a run manifest, and download sequentially."""
    config = Config()
    logger = setup_logging(config)
    click.get_current_context().meta["apkworkbench_run_id"] = ""
    click.echo(BANNER)
    click.echo("Authenticating F-Droid index before selecting APKs...")

    try:
        _client, index_data, artifacts = _load_fdroid_artifacts(config, force_refresh=refresh_index)
        index_sha256 = hashlib.sha256(index_data).hexdigest()
        database = WorkspaceDatabase(config.get("workspace"))
        database.ensure()
        previous_hashes = database.history_hashes()
        selection = select_new_artifacts(
            artifacts,
            previous_hashes,
            apk_count,
            package_filter=package_id,
        )
        if package_id:
            click.echo(f"Exact package filter: {package_id}")
        click.echo(f"Previously acquired unique binaries: {len(previous_hashes):,}")
        click.echo(f"New unique binaries available: {selection.selected_count:,}")
        if selection.shortfall:
            click.echo(
                f"SHORTFALL: requested {apk_count}, found {selection.selected_count}; "
                f"short by {selection.shortfall}."
            )
        if not selection.artifacts:
            click.echo("No new APK binaries selected; nothing to download.")
            raise click.exceptions.Exit(2 if selection.shortfall else 0)

        run_id = str(uuid.uuid4())
        selected_at = utc_now()
        downloader = ArtifactDownloader(
            database,
            workspace=config.get("workspace"),
            timeout_seconds=int(config.get("sources.fdroid.download_timeout_seconds", 60)),
        )
        manifest_rows = []
        for order, artifact in enumerate(selection.artifacts, start=1):
            manifest_rows.append(
                {
                    "run_id": run_id,
                    "selection_order": order,
                    "selected_at": selected_at,
                    "package_id": artifact.package_id,
                    "app_name": artifact.app_name or "",
                    "version_code": artifact.version_code,
                    "version_name": artifact.version_name or "",
                    "source": "fdroid",
                    "download_url": artifact.download_url,
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                    "signer_sha256": ";".join(artifact.signer_sha256),
                    "local_path": str(downloader.destination_for(artifact)),
                    "index_sha256": index_sha256,
                }
            )
        manifest_path = database.write_manifest(run_id, manifest_rows)
        # Click shares metadata between the pipeline parent and invoked stages.
        click.get_current_context().meta["apkworkbench_run_id"] = run_id
    except click.exceptions.Exit:
        raise
    except (
        DatabaseError,
        FdroidRepositoryError,
        FdroidIndexError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ) as exc:
        logger.error("APK acquisition setup failed: %s", exc)
        click.echo(f"Download setup failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("Index signature: VERIFIED")
    click.echo(f"Run ID: {run_id}")
    click.echo(f"Frozen manifest: {manifest_path}")
    click.echo("Beginning sequential downloads...")

    successes = 0
    failures = 0
    for order, artifact in enumerate(selection.artifacts, start=1):
        click.echo(
            f"[{order}/{selection.selected_count}] "
            f"{artifact.package_id} versionCode={artifact.version_code}"
        )
        try:
            result = downloader.download(
                artifact,
                run_id=run_id,
                index_sha256=index_sha256,
            )
            successes += 1
            click.echo(
                f"  VERIFIED SHA-256 {result.sha256} ({result.size:,} bytes)"
            )
            click.echo(f"  Saved: {result.path}")
        except DatabaseError as exc:
            logger.critical(
                "Acquisition stopped because workspace persistence failed for %s: %s",
                artifact.package_id,
                exc,
            )
            click.echo(f"  FATAL WORKSPACE DATABASE ERROR: {exc}", err=True)
            raise click.exceptions.Exit(1) from exc
        except DownloadError as exc:
            failures += 1
            logger.error("Download failed for %s: %s", artifact.package_id, exc)
            click.echo(f"  FAILED: {exc}", err=True)

    click.echo("")
    click.echo("ACQUISITION SUMMARY")
    click.echo(f"  Requested: {apk_count}")
    click.echo(f"  Selected: {selection.selected_count}")
    click.echo(f"  Downloaded and verified: {successes}")
    click.echo(f"  Failed: {failures}")
    click.echo(f"  Manifest: {manifest_path}")
    if failures:
        raise click.exceptions.Exit(1)
    if selection.shortfall:
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
    help="Re-run decompilation even when both tools previously succeeded.",
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
    help="Maximum number of completed APKs to scan; 0 scans all eligible downloads.",
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
    """Scan completed decompilations locally with TruffleHog; verification is disabled."""
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
        processing = database.read_processing_status()
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
    help="Number of new unique APK binaries to acquire.",
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
@click.option(
    "--refresh-index",
    is_flag=True,
    help="Ignore the local index cache and retrieve a fresh signed index.",
)
@_workspace_locked
def run(
    apk_count: int,
    package_id: str | None,
    force_decompile: bool,
    force_analyze: bool,
    refresh_index: bool,
) -> None:
    """Run discovery, acquisition, decompilation, analysis, and reporting in order."""
    context = click.get_current_context()
    context.meta["apkworkbench_run_id"] = ""
    stages_with_issues: list[str] = []
    click.echo(BANNER)
    click.echo("FULL SEQUENTIAL PIPELINE")

    for stage_name, command, kwargs in (
        ("download", download, {"apk_count": apk_count, "package_id": package_id, "refresh_index": refresh_index}),
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

    click.echo("\nFULL PIPELINE SUMMARY")
    if stages_with_issues:
        click.echo("Stages requiring attention: " + ", ".join(stages_with_issues))
        click.echo("Review 'apkworkbench status' and the per-artifact logs.")
        raise click.exceptions.Exit(1)
    click.echo("All pipeline stages completed without reported errors.")


@main.command()
def version() -> None:
    """Print the installed package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
