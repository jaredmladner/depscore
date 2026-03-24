from datetime import datetime, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.exceptions import NotFoundError
from depscore.models.enrichment import RegistryData
from depscore.models.sbom import SBOMComponent

BASE_URL = "https://api.nuget.org/v3/registration5"


class NuGetEnricher(BaseEnricher):
    async def enrich(self, component: SBOMComponent, client: httpx.AsyncClient) -> RegistryData:
        name_lower = component.name.lower()
        url = f"{BASE_URL}/{name_lower}/index.json"
        try:
            data = await self._get(client, url)
        except NotFoundError:
            return RegistryData(registry="nuget", error=f"Not found on NuGet: {component.name}")
        except Exception as exc:
            return RegistryData(registry="nuget", error=str(exc))

        items = data.get("items", [])
        if not items:
            return RegistryData(registry="nuget", error=f"Empty NuGet response for: {component.name}")

        all_versions: list[str] = []
        all_dates: list[datetime] = []

        for page in items:
            for entry in page.get("items", []):
                catalog = entry.get("catalogEntry", {})
                version = catalog.get("version")
                listed = catalog.get("listed", True)
                if version and listed:
                    all_versions.append(version)
                published = catalog.get("published")
                if published:
                    try:
                        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                        all_dates.append(dt)
                    except ValueError:
                        pass

        now = datetime.now(timezone.utc)
        latest_version = all_versions[-1] if all_versions else None
        total_versions = len(all_versions)
        first_published_days_ago = (now - min(all_dates)).days if all_dates else None
        latest_published_days_ago = (now - max(all_dates)).days if all_dates else None

        is_prerelease: bool | None = None
        if latest_version:
            is_prerelease = any(
                s in latest_version.lower()
                for s in ("alpha", "beta", "rc", "preview", "pre", "dev")
            )

        # Download stats via NuGet stats API
        weekly_downloads: int | None = None
        try:
            stats = await self._get(
                client,
                f"https://api.nuget.org/v3/stats/packages/{component.name}/downloads",
            )
            weekly_downloads = stats.get("totalDownloads")
        except Exception:
            pass

        return RegistryData(
            registry="nuget",
            latest_version=latest_version,
            total_versions=total_versions,
            first_published_days_ago=first_published_days_ago,
            latest_published_days_ago=latest_published_days_ago,
            weekly_downloads=weekly_downloads,
            is_prerelease=is_prerelease,
        )
