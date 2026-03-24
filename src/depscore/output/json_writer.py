import json
from pathlib import Path

from depscore.exceptions import OutputError
from depscore.models.report import ReportConfig
from depscore.models.scores import SBOMScoreReport


def write_json(report: SBOMScoreReport, config: ReportConfig) -> Path:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    out_path = config.output_dir / config.json_filename
    try:
        data = report.model_dump(mode="json")
        out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except OSError as exc:
        raise OutputError(f"Failed to write JSON report to {out_path}: {exc}") from exc
    return out_path
