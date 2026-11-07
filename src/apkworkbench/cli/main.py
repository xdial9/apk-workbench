"""APK Workbench command-line entry point."""
import hashlib
import uuid

import click

from apkworkbench import __version__
from apkworkbench.acquisition.downloader import ArtifactDownloader, DownloadError
from apkworkbench.acquisition.selector import select_new_artifacts
from apkworkbench.core.config import Config
from apkworkbench.core.logging import setup_logging
from apkworkbench.database.workspace import DatabaseError, WorkspaceDatabase, utc_now
from apkworkbench.decompilation.runner import DecompilationRunner
from apkworkbench.dependencies.detector import DependencyDetector
from apkworkbench.security.gpg_verifier import GpgVerifier
from apkworkbench.sources.fdroid import FdroidArtifact, FdroidIndexError, FdroidIndexParser
from apkworkbench.sources.fdroid_repository import (
    FdroidRepositoryClient,
    FdroidRepositoryError,
)


BANNER = """APK WORKBENCH
DISCOVER | DOWNLOAD | DECOMPILE | ANALYZE | CATALOGUE
CO-DEVELOPED BY dial9 + ChatGPT
SLOW. SIMPLE. SEQUENTIAL. VERIFIED."""


def _load_fdroid_artifacts(config: Config):
    """Retrieve, authenticate, and parse the configured F-Droid repository index."""
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
    )
    index_data = client.fetch_verified_index()
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
def discover(package_id: str | None, limit: int) -> None:
    """Fetch, authenticate, and summarize the official F-Droid index-v2."""
    config = Config()
    logger = setup_logging(config)
    click.echo(BANNER)
    click.echo("Retrieving the F-Droid repository index and detached signature...")

    try:
        _client, index_data, artifacts = _load_fdroid_artifacts(config)
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
def download(apk_count: int, package_id: str | None) -> None:
    """Select new APK binaries, freeze a run manifest, and download sequentially."""
    config = Config()
    logger = setup_logging(config)
    click.echo(BANNER)
    click.echo("Authenticating F-Droid index before selecting APKs...")

    try:
        client, index_data, artifacts = _load_fdroid_artifacts(config)
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
def decompile(limit: int, force: bool) -> None:
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
        summary = runner.run(limit=limit or None, force=force)
    except (DatabaseError, OSError, ValueError) as exc:
        logger.error("Decompilation run failed: %s", exc)
        click.echo(f"Decompilation failed: {exc}", err=True)
        raise click.exceptions.Exit(1) from exc

    click.echo("DECOMPILATION SUMMARY")
    click.echo(f"  Examined: {summary.examined}")
    click.echo(f"  Completed: {summary.completed}")
    click.echo(f"  Failed: {summary.failed}")
    click.echo(f"  Already complete / skipped: {summary.skipped}")
    if summary.failed:
        raise click.exceptions.Exit(1)


@main.command()
def version() -> None:
    """Print the installed package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
