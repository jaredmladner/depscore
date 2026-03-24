from datetime import datetime, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.exceptions import NotFoundError
from depscore.models.enrichment import RegistryData
from depscore.models.sbom import SBOMComponent


class NpmEnricher(BaseEnricher):
    async def enrich(self, component: SBOMComponent, client: httpx.AsyncClient) -> RegistryData:
        # npm scoped packages use %2F encoding in the registry URL
        name = component.name.replace("/", "%2F")
        url = f"https://registry.npmjs.org/{name}"
        try:
            data = await self._get(client, url)
        except NotFoundError:
            return RegistryData(registry="npm", error=f"Not found on npm: {component.name}")
        except Exception as exc:
            return RegistryData(registry="npm", error=str(exc))

        now = datetime.now(timezone.utc)

        dist_tags = data.get("dist-tags", {})
        latest_version = dist_tags.get("latest")

        time_map: dict[str, str] = data.get("time", {})
        versions = [v for v in time_map if v not in ("created", "modified")]
        total_versions = len(versions)

        first_published_days_ago: int | None = None
        latest_published_days_ago: int | None = None

        created = time_map.get("created")
        modified = time_map.get("modified")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                first_published_days_ago = (now - dt).days
            except ValueError:
                pass
        if modified:
            try:
                dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                latest_published_days_ago = (now - dt).days
            except ValueError:
                pass

        is_prerelease: bool | None = None
        if latest_version:
            is_prerelease = any(s in latest_version.lower() for s in ("alpha", "beta", "rc", "pre", "dev"))

        # Download count from downloads API
        weekly_downloads: int | None = None
        try:
            dl_data = await self._get(
                client,
                f"https://api.npmjs.org/downloads/point/last-week/{component.name}",
            )
            weekly_downloads = dl_data.get("downloads")
        except Exception:
            pass

        return RegistryData(
            registry="npm",
            latest_version=latest_version,
            total_versions=total_versions,
            first_published_days_ago=first_published_days_ago,
            latest_published_days_ago=latest_published_days_ago,
            weekly_downloads=weekly_downloads,
            is_prerelease=is_prerelease,
        )
