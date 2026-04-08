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


def _has_fix(vuln: dict) -> bool:
    """Return True if any affected range has a 'fixed' event."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return True
    return False


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

        # CVE resolution tracking
        fixed_count = 0
        days_to_fix_list: list[float] = []
        unpatched_critical = 0

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

            # --- CVE resolution speed ---
            has_fix = _has_fix(vuln)
            if has_fix:
                fixed_count += 1
                # Use published → modified delta as a proxy for time-to-fix.
                # OSV records are typically updated when a fix is released/confirmed.
                published_str = vuln.get("published")
                modified_str = vuln.get("modified")
                if published_str and modified_str:
                    try:
                        pub_dt = datetime.fromisoformat(
                            published_str.replace("Z", "+00:00")
                        )
                        mod_dt = datetime.fromisoformat(
                            modified_str.replace("Z", "+00:00")
                        )
                        delta_days = (mod_dt - pub_dt).total_seconds() / 86400
                        if delta_days >= 0:
                            days_to_fix_list.append(delta_days)
                    except ValueError:
                        pass
            elif severity == "CRITICAL":
                unpatched_critical += 1

        most_recent_days_ago: int | None = None
        if oldest_modified:
            most_recent_days_ago = (datetime.now(timezone.utc) - oldest_modified).days

        pct_fixed = (fixed_count / len(vulns)) if vulns else None
        avg_days = (
            round(sum(days_to_fix_list) / len(days_to_fix_list), 1)
            if days_to_fix_list
            else None
        )

        return OSVData(
            vuln_count_total=len(vulns),
            vuln_count_critical=counts["CRITICAL"],
            vuln_count_high=counts["HIGH"],
            vuln_count_medium=counts["MEDIUM"],
            vuln_count_low=counts["LOW"],
            most_recent_vuln_days_ago=most_recent_days_ago,
            cve_ids=list(set(cve_ids)),
            pct_vulns_fixed=pct_fixed,
            avg_days_to_fix=avg_days,
            unpatched_critical_count=unpatched_critical,
        )
