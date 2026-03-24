from pathlib import Path

from pydantic import BaseModel


class ReportConfig(BaseModel):
    output_dir: Path
    emit_json: bool = True
    emit_html: bool = False
    json_filename: str = "depscore-report.json"
    html_filename: str = "depscore-report.html"
