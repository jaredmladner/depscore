from datetime import datetime, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.exceptions import NotFoundError
from depscore.models.enrichment import LibrariesIOData
from depscore.models.sbom import SBOMComponent

BASE_URL = "https://libraries.io/api"

_PLATFORM_MAP = {
    "pypi": "Pypi",
    "npm": "NPM",
    "maven": "Maven",
    "nuget": "NuGet",
    "cargo": "Cargo",
    "gem": "Rubygems",
    "golang": "Go",
    "composer": "Packagist",
}


class LibrariesIOEnricher(BaseEnricher):
    def __init__(self, api_key: str | None, timeout: float = 30.0, max_retries: int = 3) -> None:
        super().__init__(timeout=timeout, max_retries=max_retries)
        self.api_key = api_key

    async def enrich(self, component: SBOMComponent, client: httpx.AsyncClient) -> LibrariesIOData:
        if not self.api_key:
            return LibrariesIOData(error="No Libraries.io API key configured")

        platform = _PLATFORM_MAP.get(component.ecosystem or "")
        if not platform:
            return LibrariesIOData(error=f"Unsupported ecosystem for Libraries.io: {component.ecosystem}")

        url = f"{BASE_URL}/{platform}/{component.name}"
        try:
            data = await self._get(client, url, params={"api_key": self.api_key})
        except NotFoundError:
            return LibrariesIOData(error=f"Not found on Libraries.io: {component.name}")
        except Exception as exc:
            return LibrariesIOData(error=str(exc))

        now = datetime.now(timezone.utc)

        latest_release_days_ago: int | None = None
        latest_release = data.get("latest_release_published_at")
        if latest_release:
            try:
                dt = datetime.fromisoformat(latest_release.replace("Z", "+00:00"))
                latest_release_days_ago = (now - dt).days
            except ValueError:
                pass

        first_publish_days_ago: int | None = None
        first_publish = data.get("first_publish_timestamp") or data.get("created_at")
        if first_publish:
            try:
                dt = datetime.fromisoformat(str(first_publish).replace("Z", "+00:00"))
                first_publish_days_ago = (now - dt).days
            except ValueError:
                pass

        return LibrariesIOData(
            dependent_repos_count=data.get("dependent_repos_count"),
            dependent_packages_count=data.get("dependents_count"),
            latest_release_days_ago=latest_release_days_ago,
            release_count=data.get("versions_count"),
            first_publish_days_ago=first_publish_days_ago,
            sourcerank=data.get("rank"),
        )
