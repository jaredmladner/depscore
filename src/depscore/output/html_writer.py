import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from depscore.exceptions import OutputError
from depscore.models.report import ReportConfig
from depscore.models.scores import SBOMScoreReport

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def write_html(report: SBOMScoreReport, config: ReportConfig) -> Path:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    out_path = config.output_dir / config.html_filename

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("dashboard.html.j2")

    report_json = json.dumps(report.model_dump(mode="json"), default=str)

    grade_colors = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}

    try:
        html = template.render(
            report=report,
            report_json=report_json,
            grade_colors=grade_colors,
        )
        out_path.write_text(html, encoding="utf-8")
    except OSError as exc:
        raise OutputError(f"Failed to write HTML report to {out_path}: {exc}") from exc

    return out_path
