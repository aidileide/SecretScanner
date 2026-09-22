"""Typer command-line interface."""

from __future__ import annotations

import logging
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from secretscanner import __version__
from secretscanner.config import ScannerConfig, load_config
from secretscanner.exceptions import SecretScannerError
from secretscanner.models import ScanResult, Severity
from secretscanner.reporters.baseline import load_baseline, write_baseline
from secretscanner.reporters.console import print_console
from secretscanner.reporters.json_reporter import json_report
from secretscanner.reporters.sarif import sarif_report
from secretscanner.scanner.engine import SecretScanner
from secretscanner.scanner.git import GitScanner

app = typer.Typer(
    name="secretscanner",
    help="Find secrets before they reach your repository.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
baseline_app = typer.Typer(help="Create a secret-free finding baseline.", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")
console = Console()
error_console = Console(stderr=True)
logger = logging.getLogger("secretscanner")


class OutputFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


def _scanner(
    target: Path,
    *,
    config_path: Path | None,
    baseline: Path | None,
    show_secrets: bool,
    max_file_size: int | None = None,
) -> tuple[SecretScanner, ScannerConfig]:
    config, registry, resolved = load_config(target, config_path)
    if max_file_size is not None:
        config.max_file_size_mb = max_file_size
    logger.info("configuration=%s", resolved or "defaults")
    return (
        SecretScanner(
            config,
            registry,
            show_secrets=show_secrets,
            baseline_fingerprints=load_baseline(baseline),
        ),
        config,
    )


def _finish(
    result: ScanResult,
    *,
    output_format: OutputFormat,
    output: Path | None,
    show_secrets: bool,
    fail_on: Severity,
) -> None:
    if output_format is OutputFormat.CONSOLE:
        if output:
            with output.open("w", encoding="utf-8") as handle:
                print_console(
                    result,
                    show_secrets=show_secrets,
                    console=Console(file=handle, color_system=None),
                )
        else:
            print_console(result, show_secrets=show_secrets, console=console)
    else:
        text = (
            json_report(result, show_secrets=show_secrets)
            if output_format is OutputFormat.JSON
            else sarif_report(result, show_secrets=show_secrets)
        )
        if output:
            output.write_text(text, encoding="utf-8")
            console.print(f"Report written to [cyan]{output}[/cyan]")
        else:
            typer.echo(text, nl=False)
    if result.has_at_or_above(fail_on):
        raise typer.Exit(code=1)


def _guard(operation: Callable[[], None]) -> None:
    try:
        operation()
    except typer.Exit:
        raise
    except SecretScannerError as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


@app.command("scan")
def scan_command(
    target: Annotated[Path, typer.Argument(help="File or directory to scan.")] = Path("."),
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    baseline: Annotated[Path | None, typer.Option("--baseline")] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude")] = None,
    max_file_size: Annotated[int | None, typer.Option("--max-file-size", min=1)] = None,
    follow_symlinks: Annotated[bool, typer.Option("--follow-symlinks")] = False,
    show_secrets: Annotated[bool, typer.Option("--show-secrets")] = False,
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """Scan a local file or directory recursively."""

    def execute() -> None:
        scanner, _ = _scanner(
            target,
            config_path=config_path,
            baseline=baseline,
            show_secrets=show_secrets,
            max_file_size=max_file_size,
        )
        result = scanner.scan_path(
            target,
            extra_excludes=exclude or [],
            follow_symlinks=follow_symlinks,
        )
        _finish(
            result,
            output_format=output_format,
            output=output,
            show_secrets=show_secrets,
            fail_on=fail_on,
        )

    _guard(execute)


@app.command("git")
def git_command(
    target: Annotated[Path, typer.Argument(help="Git repository path.")] = Path("."),
    include_untracked: Annotated[bool, typer.Option("--include-untracked")] = False,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    baseline: Annotated[Path | None, typer.Option("--baseline")] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    show_secrets: Annotated[bool, typer.Option("--show-secrets")] = False,
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """Scan tracked files in a Git worktree."""

    def execute() -> None:
        scanner, _ = _scanner(
            target, config_path=config_path, baseline=baseline, show_secrets=show_secrets
        )
        result = GitScanner(scanner).scan_worktree(target, include_untracked=include_untracked)
        _finish(
            result,
            output_format=output_format,
            output=output,
            show_secrets=show_secrets,
            fail_on=fail_on,
        )

    _guard(execute)


@app.command("staged")
def staged_command(
    target: Annotated[Path, typer.Argument(help="Git repository path.")] = Path("."),
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    show_secrets: Annotated[bool, typer.Option("--show-secrets")] = False,
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """Scan only added lines staged for the next commit."""

    def execute() -> None:
        scanner, _ = _scanner(
            target, config_path=config_path, baseline=None, show_secrets=show_secrets
        )
        result = GitScanner(scanner).scan_staged(target)
        _finish(
            result,
            output_format=output_format,
            output=output,
            show_secrets=show_secrets,
            fail_on=fail_on,
        )

    _guard(execute)


@app.command("history")
def history_command(
    target: Annotated[Path, typer.Argument(help="Git repository path.")] = Path("."),
    max_commits: Annotated[int, typer.Option("--max-commits", min=1)] = 100,
    since: Annotated[str | None, typer.Option("--since")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    show_secrets: Annotated[bool, typer.Option("--show-secrets")] = False,
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """Scan added lines from a bounded number of Git commits."""

    def execute() -> None:
        scanner, _ = _scanner(
            target, config_path=config_path, baseline=None, show_secrets=show_secrets
        )
        result = GitScanner(scanner).scan_history(target, max_commits=max_commits, since=since)
        _finish(
            result,
            output_format=output_format,
            output=output,
            show_secrets=show_secrets,
            fail_on=fail_on,
        )

    _guard(execute)


@baseline_app.command("create")
def baseline_create(
    target: Annotated[Path, typer.Argument(help="File or directory to scan.")] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".secretscanner-baseline.json"),
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Create a baseline containing fingerprints only."""

    def execute() -> None:
        scanner, _ = _scanner(target, config_path=config_path, baseline=None, show_secrets=False)
        result = scanner.scan_path(target)
        write_baseline(result, output)
        console.print(f"Baseline created: [cyan]{output}[/cyan] ({len(result.findings)} findings)")

    _guard(execute)


@app.command("rules")
def rules_command(
    target: Annotated[Path, typer.Option("--path")] = Path("."),
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """List active built-in and custom rules."""

    def execute() -> None:
        _, registry, _ = load_config(target, config_path)
        table = Table("ID", "Name", "Severity", "Confidence", "Enabled")
        for rule in registry.all_rules():
            table.add_row(
                rule.rule_id,
                rule.name,
                rule.severity.value,
                rule.confidence.value,
                "yes" if rule.enabled else "no",
            )
        console.print(table)

    _guard(execute)


@app.command("config")
def config_command(
    target: Annotated[Path, typer.Argument(help="Path used to resolve project config.")] = Path(
        "."
    ),
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Show resolved non-sensitive scanner settings."""

    def execute() -> None:
        config, registry, resolved = load_config(target, config_path)
        console.print(f"Config: {resolved or 'defaults'}")
        console.print(f"Max file size: {config.max_file_size_mb} MB")
        console.print(f"Entropy: {'enabled' if config.entropy else 'disabled'}")
        console.print(f"Active rules: {len(registry.rules())}")
        console.print(f"Exclude patterns: {len(config.exclude)}")

    _guard(execute)


@app.command("version")
def version_command() -> None:
    """Show installed version."""
    typer.echo(f"SecretScanner {__version__}")


@app.callback()
def main_callback(
    verbose: Annotated[int, typer.Option("-v", "--verbose", count=True)] = 0,
) -> None:
    """Configure secret-safe diagnostic logging."""
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")
