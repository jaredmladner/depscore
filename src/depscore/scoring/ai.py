"""Claude AI scoring layer.

Claude receives all enriched data for a dependency plus the rules-based scores
and returns per-dimension scores with reasoning.
"""

import json
import logging

from anthropic import AsyncAnthropic
from pydantic import BaseModel, ValidationError

from depscore.models.dependency import EnrichedDependency

logger = logging.getLogger(__name__)

MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a software supply chain security analyst specializing in open source dependency risk assessment, \
with expertise in federal and DoD software acquisition requirements (EO 14028, NIST SP 800-161, CISA guidance).

You will receive enriched metadata for a software dependency. Your task is to score it across four dimensions:
- maturity: Version stability, project age, release cadence, adoption/download statistics
- maintainability: Commit recency and frequency, issue/PR response time, bus factor (contributor concentration)
- security_posture: CVE history severity/recency, CVE fix rate and resolution speed, unpatched critical CVEs, \
security policy presence, branch protection, signed commits
- community_health: Contributor diversity, bus factor, adversarial-nation contributor presence (Russia/China/Iran/DPRK/Belarus), \
corporate concentration, ecosystem health

Each score is 0-100 (higher = better/safer). Rules-based scores are provided as a reference baseline.

Guidelines:
- Base scores on the provided data only. Do not invent information.
- Missing data fields reduce confidence; use conservative scores (pulled toward 50) when data is sparse.
- Return ONLY valid JSON matching the schema. No prose outside the JSON.
- "reasoning" fields must be 1-3 sentences citing specific signals from the data.
- You may adjust rules scores by ±15 points based on nuanced judgment.
- SECURITY POSTURE: Weight unpatched critical CVEs very heavily. A fast fix rate (low avg_days_to_fix) \
is a strong positive signal — it shows the maintainers respond to vulnerabilities. A high pct_vulns_fixed \
with low avg_days_to_fix should meaningfully boost the score.
- COMMUNITY HEALTH: Any non-zero adversarial_contributor_pct must be explicitly mentioned in reasoning. \
Even a small percentage (>0%) warrants a flag for federal/DoD consumers. Higher percentages should \
significantly lower the score. List specific adversarial_domains_found if present.
- Flag unusual patterns: sudden maintainer changes, security policy gaps, concentration of commits \
from a single nation or corporate entity.

Return exactly this JSON structure:
{
  "maturity": {"score": <float 0-100>, "confidence": <float 0-1>, "reasoning": "<string>"},
  "maintainability": {"score": <float 0-100>, "confidence": <float 0-1>, "reasoning": "<string>"},
  "security_posture": {"score": <float 0-100>, "confidence": <float 0-1>, "reasoning": "<string>"},
  "community_health": {"score": <float 0-100>, "confidence": <float 0-1>, "reasoning": "<string>"}
}"""


class _DimResult(BaseModel):
    score: float
    confidence: float
    reasoning: str


class _AIResponse(BaseModel):
    maturity: _DimResult
    maintainability: _DimResult
    security_posture: _DimResult
    community_health: _DimResult


def _build_user_message(dep: EnrichedDependency, rules_scores: dict[str, float]) -> str:
    payload: dict = {
        "dependency": {
            "name": dep.component.name,
            "version": dep.component.version,
            "ecosystem": dep.component.ecosystem,
            "purl": dep.component.purl,
        },
        "rules_scores": rules_scores,
    }

    if dep.github and not dep.github.error:
        gh = dep.github
        payload["github"] = {
            "stars": gh.stars,
            "forks": gh.forks,
            "open_issues": gh.open_issues,
            "days_since_last_commit": gh.days_since_last_commit,
            "commits_last_90_days": gh.commits_last_90_days,
            "total_contributors": gh.total_contributors,
            "top_contributor_percent": gh.top_contributor_percent,
            "has_security_md": gh.has_security_md,
            "branch_protection_enabled": gh.branch_protection_enabled,
            "signed_commits_required": gh.signed_commits_required,
            "open_pr_age_days_median": gh.open_pr_age_days_median,
            "corporate_backed": gh.corporate_backed,
            "org_name": gh.org_name,
            # Adversarial contributor signals
            "adversarial_contributor_pct": gh.adversarial_contributor_pct,
            "adversarial_domains_found": gh.adversarial_domains_found,
        }

    if dep.scorecard and not dep.scorecard.error:
        sc = dep.scorecard
        payload["scorecard"] = {
            "aggregate_score": sc.aggregate_score,
            "checks": sc.checks,
        }

    if dep.osv:
        osv = dep.osv
        payload["osv"] = {
            "vuln_count_total": osv.vuln_count_total,
            "vuln_count_critical": osv.vuln_count_critical,
            "vuln_count_high": osv.vuln_count_high,
            "vuln_count_medium": osv.vuln_count_medium,
            "vuln_count_low": osv.vuln_count_low,
            "most_recent_vuln_days_ago": osv.most_recent_vuln_days_ago,
            "cve_ids": osv.cve_ids,
            # CVE resolution speed signals
            "pct_vulns_fixed": osv.pct_vulns_fixed,
            "avg_days_to_fix": osv.avg_days_to_fix,
            "unpatched_critical_count": osv.unpatched_critical_count,
        }

    if dep.registry and not dep.registry.error:
        reg = dep.registry
        payload["registry"] = {
            "registry": reg.registry,
            "latest_version": reg.latest_version,
            "total_versions": reg.total_versions,
            "first_published_days_ago": reg.first_published_days_ago,
            "latest_published_days_ago": reg.latest_published_days_ago,
            "weekly_downloads": reg.weekly_downloads,
            "is_prerelease": reg.is_prerelease,
        }

    if dep.libraries_io and not dep.libraries_io.error:
        lib = dep.libraries_io
        payload["libraries_io"] = {
            "dependent_repos_count": lib.dependent_repos_count,
            "dependent_packages_count": lib.dependent_packages_count,
            "latest_release_days_ago": lib.latest_release_days_ago,
            "release_count": lib.release_count,
            "first_publish_days_ago": lib.first_publish_days_ago,
            "sourcerank": lib.sourcerank,
        }

    return json.dumps(payload, indent=2, default=str)


class AIScorer:
    def __init__(self, api_key: str) -> None:
        self._client = AsyncAnthropic(api_key=api_key)

    async def score(
        self,
        dep: EnrichedDependency,
        rules_scores: dict[str, float],
    ) -> _AIResponse | None:
        user_msg = _build_user_message(dep, rules_scores)
        try:
            message = await self._client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            raw = message.content[0].text.strip()
            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            parsed = _AIResponse.model_validate(json.loads(raw))
            return parsed
        except (ValidationError, json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "AI response parse error for %s: %s", dep.component.name, exc
            )
            return None
        except Exception as exc:
            logger.warning("AI scoring error for %s: %s", dep.component.name, exc)
            return None
