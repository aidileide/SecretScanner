"""Compact Chinese Rich output that never reveals secrets by default."""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secretscanner.models import SEVERITY_RANK, Finding, ScanResult

MAX_CONSOLE_FINDINGS = 100
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}


def print_console(
    result: ScanResult, *, show_secrets: bool = False, console: Console | None = None
) -> None:
    output = console or Console()
    counts = result.summary.counts(result.findings)
    output.print(
        Panel(
            Text.from_markup(
                "[bold bright_cyan]SecretScanner[/bold bright_cyan]\n"
                "[dim]在敏感信息进入仓库前发现它[/dim]"
            ),
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    output.print(_summary_table(counts))
    if result.summary.incomplete:
        output.print(
            Panel(
                f"[bold yellow]⚠ 扫描未完整完成[/bold yellow]\n"
                f"原因：{result.summary.incomplete_reason or '达到安全边界'}\n"
                f"发现 {result.summary.discovered_files} 个候选文件。",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    if not result.findings:
        output.print(
            Panel(
                "[bold green]✓ 未发现达到规则条件的敏感信息[/bold green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return

    ordered = sorted(
        result.findings,
        key=lambda item: (
            -SEVERITY_RANK[item.severity],
            item.file_path,
            item.line_number,
            item.column,
        ),
    )
    output.print(_finding_table(ordered[:MAX_CONSOLE_FINDINGS], show_secrets))
    if len(ordered) > MAX_CONSOLE_FINDINGS:
        output.print(
            f"[yellow]仅显示前 {MAX_CONSOLE_FINDINGS} 项；"
            "请使用 --format json --output report.json 查看完整脱敏报告。[/yellow]"
        )
    output.print(_remediation_panel(ordered))


def _summary_table(counts: dict[str, int | float | bool | str | None]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True, header_style="bold")
    columns = (
        ("已扫描", "scanned_files", "cyan"),
        ("已跳过", "skipped_files", "dim"),
        ("严重", "critical", "bold red"),
        ("高危", "high", "bright_red"),
        ("中危", "medium", "yellow"),
        ("低危", "low", "blue"),
        ("总计", "total", "bold"),
        ("耗时", "elapsed_seconds", "green"),
    )
    for label, _, style in columns:
        table.add_column(label, justify="center", style=style)
    values = []
    for _, key, _ in columns:
        value = counts[key]
        values.append(f"{value:.2f}s" if key == "elapsed_seconds" else str(value))
    table.add_row(*values)
    return table


def _finding_table(findings: list[Finding], show_secrets: bool) -> Table:
    table = Table(
        title="检测结果",
        box=box.ROUNDED,
        expand=True,
        header_style="bold cyan",
        row_styles=["", "dim"],
    )
    table.add_column("级别", width=6, no_wrap=True)
    table.add_column("规则", ratio=2)
    table.add_column("位置", ratio=4)
    table.add_column("置信度", width=7, no_wrap=True)
    table.add_column("匹配（已脱敏）", ratio=3, overflow="fold")
    for finding in findings:
        value = (
            finding.matched_text_revealed
            if show_secrets and finding.matched_text_revealed
            else finding.matched_text_masked
        )
        location = f"{finding.file_path}:{finding.line_number}:{finding.column}"
        if finding.commit_hash:
            location += f" @{finding.commit_hash[:12]}"
        table.add_row(
            Text(SEVERITY_LABELS[finding.severity.value], style=_color(finding.severity.value)),
            finding.rule_name,
            location,
            finding.confidence.value,
            value,
        )
    return table


def _remediation_panel(findings: list[Finding]) -> Panel:
    seen: set[str] = set()
    lines: list[Text] = []
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        lines.append(Text.assemble((f"• {finding.rule_name}: ", "bold"), finding.remediation))
    return Panel(
        Group(*lines),
        title="修复建议",
        border_style="blue",
        box=box.ROUNDED,
    )


def _color(severity: str) -> str:
    return {"critical": "bold red", "high": "bright_red", "medium": "yellow", "low": "blue"}[
        severity
    ]
