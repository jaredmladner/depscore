from datetime import datetime, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.models.enrichment import RegistryData
from depscore.models.sbom import SBOMComponent


def _parse_maven_name(name: str) -> tuple[str, str] | None:
    """Split 'group:artifact' or 'group/artifact' into (groupId, artifactId)."""
    for sep in (":", "/"):
        if sep in name:
            parts = name.split(sep, 1)
            return parts[0], parts[1]
    return None


class MavenEnricher(BaseEnricher):
    BASE = "https://search.maven.org/solrsearch/select"

    async def enrich(self, component: SBOMComponent, client: httpx.AsyncClient) -> RegistryData:
        coords = _parse_maven_name(component.name)
        if not coords:
            # Try to parse from PURL: pkg:maven/group.id/artifact.id
            if component.purl and component.purl.startswith("pkg:maven/"):
                rest = component.purl[len("pkg:maven/"):].split("@")[0]
                parts = rest.split("/")
                if len(parts) >= 2:
                    coords = (parts[0], parts[1])

        if not coords:
            return RegistryData(registry="maven", error=f"Cannot determine groupId/artifactId for: {component.name}")

        group_id, artifact_id = coords
        query = f"g:{group_id} AND a:{artifact_id}"

        try:
            data = await self._get(
                client,
                self.BASE,
                params={"q": query, "rows": "1", "wt": "json"},
            )
        except Exception as exc:
            return RegistryData(registry="maven", error=str(exc))

        response = data.get("response", {})
        docs = response.get("docs", [])
        if not docs:
            return RegistryData(registry="maven", error=f"Not found on Maven Central: {component.name}")

        doc = docs[0]
        latest_version = doc.get("latestVersion") or doc.get("v")
        total_versions = doc.get("versionCount")

        # timestamp is milliseconds since epoch
        timestamp = doc.get("timestamp")
        latest_published_days_ago: int | None = None
        if timestamp:
            try:
                dt = datetime.fromtimestamp(int(timestamp) / 1000, tz=timezone.utc)
                latest_published_days_ago = (datetime.now(timezone.utc) - dt).days
            except (ValueError, OSError):
                pass

        is_prerelease: bool | None = None
        if latest_version:
            is_prerelease = any(
                s in latest_version.lower()
                for s in ("alpha", "beta", "rc", "snapshot", "milestone", "m1", "m2")
            )

        return RegistryData(
            registry="maven",
            latest_version=latest_version,
            total_versions=total_versions,
            latest_published_days_ago=latest_published_days_ago,
            is_prerelease=is_prerelease,
        )
