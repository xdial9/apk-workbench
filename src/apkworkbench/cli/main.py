"""APK Workbench command-line entry point."""
import click

from apkworkbench import __version__
from apkworkbench.core.config import Config
from apkworkbench.core.logging import setup_logging
from apkworkbench.dependencies.detector import DependencyDetector


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
def version() -> None:
    """Print the installed package version."""
    click.echo(__version__)


if __name__ == "__main__":
    main()
