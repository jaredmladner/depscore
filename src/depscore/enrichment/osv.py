from datetime import datetime, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.models.enrichment import OSVData
from depscore.models.sbom import SBOMComponent

OSV_API = "https://api.osv.dev/v1/query"

# Maps depscore ecosystem names → OSV ecosystem names
_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "golang": "Go",
    "composer": "Packagist",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class OSVEnricher(BaseEnricher):
    async def enrich(
        self, component: SBOMComponent, client: httpx.AsyncClient
    ) -> OSVData:
        ecosystem = _ECOSYSTEM_MAP.get(component.ecosystem or "", "")
        if not ecosystem or not component.name:
            return OSVData(error="Unsupported ecosystem or missing name for OSV lookup")

        body: dict = {"package": {"name": component.name, "ecosystem": ecosystem}}
        if component.version:
            body["version"] = component.version

        try:
            data = await self._post(client, OSV_API, body)
        except Exception as exc:
            return OSVData(error=str(exc))

        vulns = data.get("vulns", [])
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cve_ids: list[str] = []
        oldest_modified: datetime | None = None

        for vuln in vulns:
            # Collect CVE IDs
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_ids.append(alias)

            # Determine severity
            severity = "LOW"
            for sev in vuln.get("severity", []):
                sev_type = sev.get("type", "")
                sev_score = sev.get("score", "")
                if sev_type == "CVSS_V3" and sev_score:
                    try:
                        score = float(sev_score)
                        if score >= 9.0:
                            severity = "CRITICAL"
                        elif score >= 7.0:
                            severity = "HIGH"
                        elif score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    except ValueError:
                        pass
                    break

            counts[severity] += 1

            # Track most recent vuln date
            modified = vuln.get("modified") or vuln.get("published")
            if modified:
                try:
                    dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                    if oldest_modified is None or dt > oldest_modified:
                        oldest_modified = dt
                except ValueError:
                    pass

        most_recent_days_ago: int | None = None
        if oldest_modified:
            most_recent_days_ago = (datetime.now(timezone.utc) - oldest_modified).days

        return OSVData(
            vuln_count_total=len(vulns),
            vuln_count_critical=counts["CRITICAL"],
            vuln_count_high=counts["HIGH"],
            vuln_count_medium=counts["MEDIUM"],
            vuln_count_low=counts["LOW"],
            most_recent_vuln_days_ago=most_recent_days_ago,
            cve_ids=list(set(cve_ids)),
        )
