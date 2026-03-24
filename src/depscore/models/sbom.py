from typing import Any, Literal

from pydantic import BaseModel


class SBOMComponent(BaseModel):
    name: str
    version: str | None = None
    purl: str | None = None
    ecosystem: str | None = None  # pypi, npm, maven, nuget, cargo, gem, github, unknown
    repository_url: str | None = None
    license: str | None = None


class ParsedSBOM(BaseModel):
    format: Literal["cyclonedx", "spdx"]
    spec_version: str
    serial_number: str | None = None
    components: list[SBOMComponent]
    metadata: dict[str, Any] = {}
