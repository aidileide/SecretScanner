"""Readable Rich terminal output that never reveals secrets by default."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secretscanner.models import ScanResult


def print_console(
    result: ScanResult, *, show_secrets: bool = False, console: Console | None = None
) -> None:
    output = console or Console()
    output.print("[bold cyan]SecretScanner[/bold cyan]")
    if not result.findings:
        output.print("[green]No secrets detected.[/green]")
    for finding in result.findings:
        value = (
            finding.matched_text_revealed
            if show_secrets and finding.matched_text_revealed
            else finding.matched_text_masked
        )
        location = f"{finding.file_path}:{finding.line_number}:{finding.column}"
        commit = f"\nCommit: {finding.commit_hash[:12]}" if finding.commit_hash else ""
        output.print(
            Panel(
                f"[bold]{finding.rule_name}[/bold]\n{location}{commit}\n\n"
                f"[yellow]{value}[/yellow]\n\nRecommendation: {finding.remediation}",
                title=finding.severity.value.upper(),
                border_style=_color(finding.severity.value),
            )
        )
    counts = result.summary.counts(result.findings)
    table = Table(title="Summary", show_header=False)
    for label, key in (
        ("Scanned files", "scanned_files"),
        ("Skipped files", "skipped_files"),
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Total", "total"),
        ("Elapsed", "elapsed_seconds"),
    ):
        value = counts[key]
        table.add_row(label, f"{value}s" if key == "elapsed_seconds" else str(value))
    output.print(table)


def _color(severity: str) -> str:
    return {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue"}[severity]
