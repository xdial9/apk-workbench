"""APK Workbench command-line entry point."""
import hashlib

import click

from apkworkbench import __version__
from apkworkbench.core.config import Config
from apkworkbench.core.logging import setup_logging
from apkworkbench.dependencies.detector import DependencyDetector
from apkworkbench.security.gpg_verifier import GpgVerifier
from apkworkbench.sources.fdroid import FdroidIndexParser, FdroidIndexError, FdroidArtifact
from apkworkbench.sources.fdroid_repository import (
    FdroidRepositoryClient,
    FdroidRepositoryError,
)


BANNER = """APK WORKBENCH
DISCOVER | DOWNLOAD | DECOMPILE | ANALYZE | CATALOGUE
CO-DEVELOPED BY dial9 + ChatGPT
SLOW. SIMPLE. SEQUENTIAL. VERIFIED."""


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
    source = config.get("sources.fdroid", {})
    repository_url = str(source.get("repository_url", "https://f-droid.org/repo"))

    click.echo(BANNER)
    click.echo("Retrieving the F-Droid repository index and detached signature...")

    try:
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
def version() -> None:
    """Print the installed package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
