from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class DimensionScore(BaseModel):
    score: float  # 0-100
    confidence: float  # 0-1
    reasoning: str
    signals: dict[str, Any] = {}


class DependencyScores(BaseModel):
    dependency_name: str
    version: str | None
    purl: str | None
    ecosystem: str | None
    maturity: DimensionScore
    maintainability: DimensionScore
    security_posture: DimensionScore
    community_health: DimensionScore
    overall: float
    overall_grade: Literal["A", "B", "C", "D", "F"]
    rules_scores: dict[str, float]
    ai_scores: dict[str, float] | None = None
    ai_reasoning: str | None = None
    ai_available: bool = True
    ai_error: str | None = None
    blend_weights: dict[str, float] = {}
    scored_at: datetime


class SBOMScoreReport(BaseModel):
    sbom_metadata: dict[str, Any]
    total_dependencies: int
    overall_sbom_score: float
    overall_sbom_grade: Literal["A", "B", "C", "D", "F"]
    grade_distribution: dict[str, int]
    dimension_averages: dict[str, float]
    scores: list[DependencyScores]
    generated_at: datetime
    depscore_version: str
