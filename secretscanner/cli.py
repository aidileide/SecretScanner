"""Typer command-line interface."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from secretscanner import __version__
from secretscanner.config import ScannerConfig, load_config
from secretscanner.exceptions import SecretScannerError
from secretscanner.models import ScanProgress, ScanResult, Severity
from secretscanner.reporters.baseline import load_baseline, write_baseline
from secretscanner.reporters.console import print_console
from secretscanner.reporters.json_reporter import json_report
from secretscanner.reporters.sarif import sarif_report
from secretscanner.scanner.engine import SecretScanner
from secretscanner.scanner.git import GitScanner

app = typer.Typer(
    name="secretscanner",
    help="在敏感信息进入仓库前发现它。",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
baseline_app = typer.Typer(help="创建不含明文敏感信息的基线。", no_args_is_help=True)
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
    workers: int | None = None,
    max_files: int | None = None,
    timeout_seconds: int | None = None,
) -> tuple[SecretScanner, ScannerConfig]:
    config, registry, resolved = load_config(target, config_path)
    if max_file_size is not None:
        config.max_file_size_mb = max_file_size
    if workers is not None:
        config.workers = workers
    if max_files is not None:
        config.max_files = max_files
    if timeout_seconds is not None:
        config.timeout_seconds = timeout_seconds
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
            console.print(f"报告已写入 [cyan]{output}[/cyan]")
        else:
            typer.echo(text, nl=False)
    if result.summary.incomplete:
        raise typer.Exit(code=2)
    if result.has_at_or_above(fail_on):
        raise typer.Exit(code=1)


def _guard(operation: Callable[[], None]) -> None:
    try:
        operation()
    except typer.Exit:
        raise
    except SecretScannerError as exc:
        error_console.print(f"[red]错误：[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        error_console.print(f"[red]错误：[/red] {exc}")
        raise typer.Exit(code=2) from exc


@contextmanager
def _progress_display(enabled: bool) -> Iterator[Callable[[ScanProgress], None] | None]:
    if not enabled:
        yield None
        return
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TextColumn("[green]扫描 {task.fields[scanned]}[/green]"),
        TextColumn("[dim]跳过 {task.fields[skipped]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as display:
        task = display.add_task("正在发现文件…", total=1, scanned=0, skipped=0)

        def update(state: ScanProgress) -> None:
            current = Path(state.current_file).name if state.current_file else "准备扫描"
            display.update(
                task,
                total=max(1, state.total_files),
                completed=state.completed_files,
                description=f"正在扫描：{current[:36]}",
                scanned=state.scanned_files,
                skipped=state.skipped_files,
            )

        yield update


@app.command("scan")
def scan_command(
    target: Annotated[Path, typer.Argument(help="要扫描的文件或目录。")] = Path("."),
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    baseline: Annotated[Path | None, typer.Option("--baseline")] = None,
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude")] = None,
    max_file_size: Annotated[int | None, typer.Option("--max-file-size", min=1)] = None,
    workers: Annotated[int | None, typer.Option("--workers", min=1, max=32)] = None,
    max_files: Annotated[int | None, typer.Option("--max-files", min=1)] = None,
    timeout_seconds: Annotated[int | None, typer.Option("--timeout", min=1)] = None,
    follow_symlinks: Annotated[bool, typer.Option("--follow-symlinks")] = False,
    show_secrets: Annotated[bool, typer.Option("--show-secrets")] = False,
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """递归扫描本地文件或目录。"""

    def execute() -> None:
        scanner, _ = _scanner(
            target,
            config_path=config_path,
            baseline=baseline,
            show_secrets=show_secrets,
            max_file_size=max_file_size,
            workers=workers,
            max_files=max_files,
            timeout_seconds=timeout_seconds,
        )
        show_progress = console.is_terminal and (
            output_format is OutputFormat.CONSOLE or output is not None
        )
        with _progress_display(show_progress) as progress:
            result = scanner.scan_path(
                target,
                extra_excludes=exclude or [],
                follow_symlinks=follow_symlinks,
                workers=workers,
                max_files=max_files,
                timeout_seconds=timeout_seconds,
                progress=progress,
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
        console.print(f"基线已创建：[cyan]{output}[/cyan]（{len(result.findings)} 项）")

    _guard(execute)


@app.command("rules")
def rules_command(
    target: Annotated[Path, typer.Option("--path")] = Path("."),
    config_path: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """List active built-in and custom rules."""

    def execute() -> None:
        _, registry, _ = load_config(target, config_path)
        table = Table("规则 ID", "名称", "级别", "置信度", "已启用")
        for rule in registry.all_rules():
            table.add_row(
                rule.rule_id,
                rule.name,
                rule.severity.value,
                rule.confidence.value,
                "是" if rule.enabled else "否",
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
        console.print(f"配置文件：{resolved or '默认配置'}")
        console.print(f"单文件上限：{config.max_file_size_mb} MB")
        console.print(f"并发线程：{config.workers}")
        console.print(f"文件总量上限：{config.max_files}")
        console.print(f"时间上限：{config.timeout_seconds or '不限制'}")
        console.print(f"单规则单文件上限：{config.max_findings_per_rule_per_file}")
        console.print(f"熵检测：{'启用' if config.entropy else '关闭'}")
        console.print(f"启用规则：{len(registry.rules())}")
        console.print(f"排除模式：{len(config.exclude)}")

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
