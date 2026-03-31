from datetime import datetime, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.exceptions import NotFoundError
from depscore.models.enrichment import RegistryData
from depscore.models.sbom import SBOMComponent

_PRE_SUFFIXES = ("a", "b", "rc", "alpha", "beta", "dev", "post")


def _is_prerelease(version: str | None) -> bool | None:
    if not version:
        return None
    v = version.lower()
    return any(s in v for s in _PRE_SUFFIXES)


class PyPIEnricher(BaseEnricher):
    async def enrich(
        self, component: SBOMComponent, client: httpx.AsyncClient
    ) -> RegistryData:
        url = f"https://pypi.org/pypi/{component.name}/json"
        try:
            data = await self._get(client, url)
        except NotFoundError:
            return RegistryData(
                registry="pypi", error=f"Not found on PyPI: {component.name}"
            )
        except Exception as exc:
            return RegistryData(registry="pypi", error=str(exc))

        info = data.get("info", {})
        releases = data.get("releases", {})
        now = datetime.now(timezone.utc)

        latest_version = info.get("version")

        # Count non-yanked versions
        total_versions = sum(
            1
            for files in releases.values()
            if files and not all(f.get("yanked", False) for f in files)
        )

        # Find first publish date (oldest release with upload_time)
        first_published_days_ago: int | None = None
        latest_published_days_ago: int | None = None
        all_dates: list[datetime] = []
        for files in releases.values():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        all_dates.append(dt)
                    except ValueError:
                        pass
        if all_dates:
            first_published_days_ago = (now - min(all_dates)).days
            latest_published_days_ago = (now - max(all_dates)).days

        return RegistryData(
            registry="pypi",
            latest_version=latest_version,
            total_versions=total_versions,
            first_published_days_ago=first_published_days_ago,
            latest_published_days_ago=latest_published_days_ago,
            is_prerelease=_is_prerelease(latest_version),
        )
