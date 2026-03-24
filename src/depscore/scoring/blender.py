"""Hybrid score blending: combines rules-based and AI scores into final scores."""

import asyncio
from datetime import datetime, timezone

from depscore.models.dependency import EnrichedDependency
from depscore.models.scores import DependencyScores, DimensionScore, SBOMScoreReport
from depscore.scoring import rules as rules_mod
from depscore.scoring.ai import AIScorer
from depscore.scoring.weights import (
    DEFAULT_BLEND_WEIGHTS,
    DEFAULT_DIMENSION_WEIGHTS,
    score_to_grade,
)

from depscore import __version__

DIMENSIONS = ["maturity", "maintainability", "security_posture", "community_health"]


def _rules_score_dep(dep: EnrichedDependency) -> dict[str, tuple[float, float, dict]]:
    return {
        "maturity": rules_mod.score_maturity(dep),
        "maintainability": rules_mod.score_maintainability(dep),
        "security_posture": rules_mod.score_security_posture(dep),
        "community_health": rules_mod.score_community_health(dep),
    }


def _blend(rules_score: float, ai_score: float | None, ai_weight: float) -> float:
    if ai_score is None:
        return rules_score
    return (rules_score * (1.0 - ai_weight)) + (ai_score * ai_weight)


async def score_dependency(
    dep: EnrichedDependency,
    ai_scorer: AIScorer | None,
    ai_weight: float,
) -> DependencyScores:
    raw_rules = _rules_score_dep(dep)
    rules_scores = {dim: raw_rules[dim][0] for dim in DIMENSIONS}
    rules_confidences = {dim: raw_rules[dim][1] for dim in DIMENSIONS}
    rules_signals = {dim: raw_rules[dim][2] for dim in DIMENSIONS}

    ai_result = None
    ai_available = True
    ai_error: str | None = None
    if ai_scorer:
        ai_result = await ai_scorer.score(dep, rules_scores)
        if ai_result is None:
            ai_available = False
            ai_error = "AI scoring failed or returned invalid response"

    ai_scores: dict[str, float] | None = None
    if ai_result:
        ai_scores = {
            "maturity": ai_result.maturity.score,
            "maintainability": ai_result.maintainability.score,
            "security_posture": ai_result.security_posture.score,
            "community_health": ai_result.community_health.score,
        }

    effective_ai_weight = ai_weight if (ai_result is not None) else 0.0

    dim_scores: dict[str, DimensionScore] = {}
    for dim in DIMENSIONS:
        r_score = rules_scores[dim]
        a_score = ai_scores[dim] if ai_scores else None
        blended = _blend(r_score, a_score, effective_ai_weight)

        reasoning = ""
        if ai_result:
            ai_dim = getattr(ai_result, dim)
            reasoning = ai_dim.reasoning
            ai_confidence = ai_dim.confidence
        else:
            reasoning = f"Rules-only score (AI unavailable). Key signals: {rules_signals[dim]}"
            ai_confidence = 0.0

        confidence = rules_confidences[dim]
        if ai_result:
            confidence = (confidence + ai_confidence) / 2

        dim_scores[dim] = DimensionScore(
            score=round(blended, 2),
            confidence=round(confidence, 3),
            reasoning=reasoning,
            signals=rules_signals[dim],
        )

    overall = sum(
        dim_scores[dim].score * DEFAULT_DIMENSION_WEIGHTS[dim]
        for dim in DIMENSIONS
    )
    overall = round(overall, 2)

    blend_weights = {
        "rules": round(1.0 - effective_ai_weight, 2),
        "ai": round(effective_ai_weight, 2),
    }

    ai_reasoning: str | None = None
    if ai_result:
        ai_reasoning = " | ".join(
            f"{dim}: {getattr(ai_result, dim).reasoning}"
            for dim in DIMENSIONS
        )

    return DependencyScores(
        dependency_name=dep.component.name,
        version=dep.component.version,
        purl=dep.component.purl,
        ecosystem=dep.component.ecosystem,
        maturity=dim_scores["maturity"],
        maintainability=dim_scores["maintainability"],
        security_posture=dim_scores["security_posture"],
        community_health=dim_scores["community_health"],
        overall=overall,
        overall_grade=score_to_grade(overall),
        rules_scores=rules_scores,
        ai_scores=ai_scores,
        ai_reasoning=ai_reasoning,
        ai_available=ai_available,
        ai_error=ai_error,
        blend_weights=blend_weights,
        scored_at=datetime.now(timezone.utc),
    )


async def score_all(
    deps: list[EnrichedDependency],
    ai_scorer: AIScorer | None,
    ai_weight: float,
    sbom_metadata: dict,
    concurrency: int = 10,
) -> SBOMScoreReport:
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded_score(dep: EnrichedDependency) -> DependencyScores:
        async with semaphore:
            return await score_dependency(dep, ai_scorer, ai_weight)

    scored = await asyncio.gather(*[_bounded_score(d) for d in deps])

    overall_sbom = (
        sum(s.overall for s in scored) / len(scored) if scored else 0.0
    )
    overall_sbom = round(overall_sbom, 2)

    grade_dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for s in scored:
        grade_dist[s.overall_grade] = grade_dist.get(s.overall_grade, 0) + 1

    dim_averages: dict[str, float] = {}
    for dim in DIMENSIONS:
        vals = [getattr(s, dim).score for s in scored]
        dim_averages[dim] = round(sum(vals) / len(vals), 2) if vals else 0.0

    return SBOMScoreReport(
        sbom_metadata=sbom_metadata,
        total_dependencies=len(scored),
        overall_sbom_score=overall_sbom,
        overall_sbom_grade=score_to_grade(overall_sbom),
        grade_distribution=grade_dist,
        dimension_averages=dim_averages,
        scores=list(scored),
        generated_at=datetime.now(timezone.utc),
        depscore_version=__version__,
    )
