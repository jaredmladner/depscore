"""depscore CLI entry point."""

import asyncio
import sys
from pathlib import Path
from typing import Literal

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from depscore import __version__
from depscore.exceptions import ConfigurationError, DepscoreError, SBOMParseError

console = Console()
err_console = Console(stderr=True)


def _parse_sbom(sbom_path: Path, fmt: Literal["cyclonedx", "spdx", "auto"]):
    from depscore.parsers.cyclonedx import CycloneDXParser
    from depscore.parsers.spdx import SPDXParser

    if fmt == "auto":
        text = sbom_path.read_text(encoding="utf-8", errors="ignore")
        fmt = "cyclonedx" if "CycloneDX" in text or "bomFormat" in text else "spdx"

    if fmt == "cyclonedx":
        return CycloneDXParser().parse(sbom_path)
    else:
        return SPDXParser().parse(sbom_path)


async def _run_scan(
    sbom_path: Path,
    fmt: str,
    output_dir: Path,
    emit_html: bool,
    no_ai: bool,
) -> int:
    from depscore.config import get_settings
    from depscore.enrichment.pipeline import enrich_all
    from depscore.models.report import ReportConfig
    from depscore.output.json_writer import write_json
    from depscore.scoring.ai import AIScorer
    from depscore.scoring.blender import score_all

    try:
        settings = get_settings()
    except ConfigurationError as exc:
        err_console.print(Panel(str(exc), title="[red]Configuration Error[/red]", border_style="red"))
        return 1

    try:
        parsed = _parse_sbom(sbom_path, fmt)  # type: ignore[arg-type]
    except SBOMParseError as exc:
        err_console.print(Panel(str(exc), title="[red]SBOM Parse Error[/red]", border_style="red"))
        return 1

    console.print(f"\n[bold]depscore[/bold] v{__version__}  |  [cyan]{sbom_path.name}[/cyan]  |  [green]{len(parsed.components)}[/green] components found\n")

    # --- Phase 1: Enrichment ---
    enriched_deps = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Enriching dependencies…", total=len(parsed.components))

        def on_progress(completed: int, total: int, name: str) -> None:
            progress.update(task, completed=completed, description=f"Enriching [cyan]{name}[/cyan]")

        enriched_deps = await enrich_all(parsed.components, settings, progress_callback=on_progress)

    console.print(f"[green]✓[/green] Enrichment complete ({len(enriched_deps)} dependencies)\n")

    # --- Phase 2: Scoring ---
    ai_scorer = None
    if not no_ai and settings.ai_enabled:
        ai_scorer = AIScorer(api_key=settings.anthropic_api_key)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        score_task = progress.add_task("Scoring dependencies…", total=len(enriched_deps))

        # Wrap score_all to show progress (it runs concurrently so we track after)
        report = await score_all(
            enriched_deps,
            ai_scorer=ai_scorer,
            ai_weight=settings.ai_blend_weight if (ai_scorer and not no_ai) else 0.0,
            sbom_metadata=parsed.metadata,
            concurrency=settings.concurrency_limit,
        )
        progress.update(score_task, completed=len(enriched_deps))

    console.print("[green]✓[/green] Scoring complete\n")

    # --- Phase 3: Output ---
    report_config = ReportConfig(
        output_dir=output_dir,
        emit_json=True,
        emit_html=emit_html,
    )

    json_path = write_json(report, report_config)
    console.print(f"[green]✓[/green] JSON report: [cyan]{json_path}[/cyan]")

    if emit_html:
        from depscore.output.html_writer import write_html
        html_path = write_html(report, report_config)
        console.print(f"[green]✓[/green] HTML report: [cyan]{html_path}[/cyan]")

    # --- Summary table ---
    table = Table(title="\nSBOM Score Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim", width=28)
    table.add_column("Value", justify="right")

    grade_color = {"A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
    g = report.overall_sbom_grade
    table.add_row("Overall SBOM Score", f"[bold]{report.overall_sbom_score:.1f}[/bold]")
    table.add_row("Overall Grade", f"[{grade_color.get(g,'white')} bold]{g}[/]")
    table.add_row("Total Dependencies", str(report.total_dependencies))
    table.add_row("", "")
    for dim, avg in report.dimension_averages.items():
        table.add_row(dim.replace("_", " ").title(), f"{avg:.1f}")
    table.add_row("", "")
    for grade, count in report.grade_distribution.items():
        c = grade_color.get(grade, "white")
        table.add_row(f"  Grade {grade}", f"[{c}]{count}[/]")

    console.print(table)
    return 0


@click.group()
@click.version_option(__version__, prog_name="depscore")
def main() -> None:
    """depscore — AI-powered SBOM dependency scoring."""


@main.command()
@click.option("--sbom", required=True, type=click.Path(exists=True, path_type=Path), help="Path to the SBOM file")
@click.option(
    "--format", "fmt",
    type=click.Choice(["cyclonedx", "spdx", "auto"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="SBOM format (auto-detected if omitted)",
)
@click.option("--output", "output_dir", default="./depscore-output", type=click.Path(path_type=Path), show_default=True, help="Output directory")
@click.option("--html", "emit_html", is_flag=True, default=False, help="Also generate an HTML dashboard")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI scoring (rules-based only, faster)")
def scan(sbom: Path, fmt: str, output_dir: Path, emit_html: bool, no_ai: bool) -> None:
    """Scan an SBOM and score all dependencies."""
    try:
        exit_code = asyncio.run(_run_scan(sbom, fmt, output_dir, emit_html, no_ai))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except DepscoreError as exc:
        err_console.print(Panel(str(exc), title="[red]Error[/red]", border_style="red"))
        sys.exit(1)
