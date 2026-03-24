from pydantic import BaseModel

from depscore.models.enrichment import (
    GitHubData,
    LibrariesIOData,
    OSVData,
    RegistryData,
    ScorecardData,
)
from depscore.models.sbom import SBOMComponent


class EnrichedDependency(BaseModel):
    component: SBOMComponent
    github: GitHubData | None = None
    scorecard: ScorecardData | None = None
    osv: OSVData | None = None
    libraries_io: LibrariesIOData | None = None
    registry: RegistryData | None = None
    enrichment_errors: list[str] = []
    enrichment_duration_seconds: float | None = None
