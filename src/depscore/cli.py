"""depscore CLI entry point."""

import asyncio
import sys
from pathlib import Path
from typing import Literal

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
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


# Grade ordering for gate comparisons (higher index = worse)
_GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _gate_violations(
    report, fail_on_grade: str
) -> list:
    """Return scored deps whose overall_grade is at or below fail_on_grade."""
    threshold = _GRADE_ORDER[fail_on_grade.upper()]
    return [
        s for s in report.scores if _GRADE_ORDER.get(s.overall_grade, 4) >= threshold
    ]


async def _run_scan(
    sbom_path: Path,
    fmt: str,
    output_dir: Path,
    emit_html: bool,
    no_ai: bool,
    ignore_file: Path | None,
    fail_on_grade: str | None,
    gate_exit_code: int,
) -> int:
    from depscore.config import get_settings
    from depscore.enrichment.pipeline import enrich_all
    from depscore.ignore import filter_components, load_ignore_patterns
    from depscore.models.report import ReportConfig
    from depscore.output.json_writer import write_json
    from depscore.scoring.ai import AIScorer
    from depscore.scoring.blender import score_all

    try:
        settings = get_settings()
    except ConfigurationError as exc:
        err_console.print(
            Panel(str(exc), title="[red]Configuration Error[/red]", border_style="red")
        )
        return 1

    try:
        parsed = _parse_sbom(sbom_path, fmt)  # type: ignore[arg-type]
    except SBOMParseError as exc:
        err_console.print(
            Panel(str(exc), title="[red]SBOM Parse Error[/red]", border_style="red")
        )
        return 1

    # --- Ignore file ---
    # Search order: explicit --ignore-file, then .depscoreignore next to SBOM, then CWD
    if ignore_file is None:
        candidate = sbom_path.parent / ".depscoreignore"
        ignore_file = candidate if candidate.exists() else None

    ignore_patterns = load_ignore_patterns(ignore_file)
    active_components, ignored_deps = filter_components(
        parsed.components, ignore_patterns
    )

    console.print(
        f"\n[bold]depscore[/bold] v{__version__}  |  [cyan]{sbom_path.name}[/cyan]  "
        f"|  [green]{len(parsed.components)}[/green] components"
        + (
            f"  |  [yellow]{len(ignored_deps)} ignored[/yellow]"
            if ignored_deps
            else ""
        )
        + "\n"
    )

    if ignore_patterns and ignored_deps:
        console.print(
            f"[dim]Ignore file: {ignore_file}  ({len(ignore_patterns)} patterns, "
            f"{len(ignored_deps)} deps skipped)[/dim]\n"
        )

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
        task = progress.add_task(
            "Enriching dependencies…", total=len(active_components)
        )

        def on_progress(completed: int, total: int, name: str) -> None:
            progress.update(
                task, completed=completed, description=f"Enriching [cyan]{name}[/cyan]"
            )

        enriched_deps = await enrich_all(
            active_components, settings, progress_callback=on_progress
        )

    console.print(
        f"[green]✓[/green] Enrichment complete ({len(enriched_deps)} dependencies)\n"
    )

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
        score_task = progress.add_task(
            "Scoring dependencies…", total=len(enriched_deps)
        )

        report = await score_all(
            enriched_deps,
            ai_scorer=ai_scorer,
            ai_weight=settings.ai_blend_weight if (ai_scorer and not no_ai) else 0.0,
            sbom_metadata=parsed.metadata,
            concurrency=settings.concurrency_limit,
        )
        progress.update(score_task, completed=len(enriched_deps))

    # Attach ignored deps to the report
    report.ignored_dependencies = ignored_deps

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
    table = Table(
        title="\nSBOM Score Summary", show_header=True, header_style="bold cyan"
    )
    table.add_column("Metric", style="dim", width=28)
    table.add_column("Value", justify="right")

    grade_color = {"A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
    g = report.overall_sbom_grade
    table.add_row("Overall SBOM Score", f"[bold]{report.overall_sbom_score:.1f}[/bold]")
    table.add_row("Overall Grade", f"[{grade_color.get(g, 'white')} bold]{g}[/]")
    table.add_row("Total Dependencies", str(report.total_dependencies))
    if ignored_deps:
        table.add_row("Ignored", f"[yellow]{len(ignored_deps)}[/yellow]")
    table.add_row("", "")
    for dim, avg in report.dimension_averages.items():
        table.add_row(dim.replace("_", " ").title(), f"{avg:.1f}")
    table.add_row("", "")
    for grade, count in report.grade_distribution.items():
        c = grade_color.get(grade, "white")
        table.add_row(f"  Grade {grade}", f"[{c}]{count}[/]")

    console.print(table)

    # --- Gate check ---
    if fail_on_grade:
        violations = _gate_violations(report, fail_on_grade)
        if violations:
            err_console.print(
                f"\n[red bold]Gate failure:[/red bold] "
                f"{len(violations)} dependenc{'y' if len(violations) == 1 else 'ies'} "
                f"scored grade [bold]{fail_on_grade.upper()}[/bold] or worse:\n"
            )
            vtable = Table(show_header=True, header_style="bold red")
            vtable.add_column("Dependency", style="cyan")
            vtable.add_column("Version")
            vtable.add_column("Grade", justify="center")
            vtable.add_column("Score", justify="right")
            for v in violations:
                gc = grade_color.get(v.overall_grade, "white")
                vtable.add_row(
                    v.dependency_name,
                    v.version or "—",
                    f"[{gc} bold]{v.overall_grade}[/]",
                    f"{v.overall:.1f}",
                )
            err_console.print(vtable)
            err_console.print(
                f"\n[red]Exiting with code {gate_exit_code}[/red] "
                f"(--fail-on-grade {fail_on_grade.upper()})\n"
            )
            return gate_exit_code

    return 0


@click.group()
@click.version_option(__version__, prog_name="depscore")
def main() -> None:
    """depscore — AI-powered SBOM dependency scoring."""


@main.command()
@click.option(
    "--sbom",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to the SBOM file",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["cyclonedx", "spdx", "auto"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="SBOM format (auto-detected if omitted)",
)
@click.option(
    "--output",
    "output_dir",
    default="./depscore-output",
    type=click.Path(path_type=Path),
    show_default=True,
    help="Output directory",
)
@click.option(
    "--html",
    "emit_html",
    is_flag=True,
    default=False,
    help="Also generate an HTML dashboard",
)
@click.option(
    "--no-ai",
    is_flag=True,
    default=False,
    help="Skip AI scoring (rules-based only, faster)",
)
@click.option(
    "--ignore-file",
    "ignore_file",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help="Path to ignore file (default: .depscoreignore next to SBOM or in CWD)",
)
@click.option(
    "--fail-on-grade",
    "fail_on_grade",
    default=None,
    type=click.Choice(["A", "B", "C", "D", "F"], case_sensitive=False),
    help="Exit with non-zero if any dependency scores at or below this grade (e.g. F, D).",
)
@click.option(
    "--exit-code",
    "gate_exit_code",
    default=1,
    show_default=True,
    type=click.IntRange(1, 255),
    help="Exit code to use when --fail-on-grade gate triggers.",
)
def scan(
    sbom: Path,
    fmt: str,
    output_dir: Path,
    emit_html: bool,
    no_ai: bool,
    ignore_file: Path | None,
    fail_on_grade: str | None,
    gate_exit_code: int,
) -> None:
    """Scan an SBOM and score all dependencies."""
    try:
        exit_code = asyncio.run(
            _run_scan(
                sbom, fmt, output_dir, emit_html, no_ai,
                ignore_file, fail_on_grade, gate_exit_code,
            )
        )
        sys.exit(exit_code)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except DepscoreError as exc:
        err_console.print(Panel(str(exc), title="[red]Error[/red]", border_style="red"))
        sys.exit(1)
