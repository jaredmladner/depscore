import re

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.exceptions import NotFoundError
from depscore.models.enrichment import ScorecardData
from depscore.models.sbom import SBOMComponent

_GITHUB_URL_RE = re.compile(r"github\.com[/:]([^/]+)/([^/.\s]+)")

BASE_URL = "https://api.securityscorecards.dev"


def _extract_github_repo(component: SBOMComponent) -> str | None:
    for url in filter(None, [component.repository_url]):
        m = _GITHUB_URL_RE.search(url)
        if m:
            return f"github.com/{m.group(1)}/{m.group(2).rstrip('.git')}"
    if component.purl and component.purl.startswith("pkg:github/"):
        rest = component.purl[len("pkg:github/"):].split("@")[0]
        parts = rest.split("/")
        if len(parts) >= 2:
            return f"github.com/{parts[0]}/{parts[1]}"
    return None


class ScorecardEnricher(BaseEnricher):
    async def enrich(self, component: SBOMComponent, client: httpx.AsyncClient) -> ScorecardData:
        repo = _extract_github_repo(component)
        if not repo:
            return ScorecardData(error="No GitHub repo found for Scorecard lookup")

        try:
            data = await self._get(client, f"{BASE_URL}/projects/{repo}")
        except NotFoundError:
            return ScorecardData(repo=repo, error="Not found in OpenSSF Scorecard")
        except Exception as exc:
            return ScorecardData(repo=repo, error=str(exc))

        aggregate = None
        score_val = data.get("score")
        if score_val is not None:
            try:
                aggregate = float(score_val)
            except (TypeError, ValueError):
                pass

        checks: dict[str, float] = {}
        for check in data.get("checks", []):
            name = check.get("name", "")
            score = check.get("score")
            if name and score is not None:
                try:
                    checks[name] = float(score)
                except (TypeError, ValueError):
                    pass

        return ScorecardData(
            repo=repo,
            date=data.get("date"),
            aggregate_score=aggregate,
            checks=checks,
        )
