"""Tests for enrichers using mocked HTTP responses."""

import pytest
import respx
import httpx

from depscore.enrichment.osv import OSVEnricher
from depscore.enrichment.pypi import PyPIEnricher
from depscore.enrichment.scorecard import ScorecardEnricher
from depscore.models.sbom import SBOMComponent


def _make_component(**kwargs) -> SBOMComponent:
    return SBOMComponent(
        name=kwargs.get("name", "requests"),
        version=kwargs.get("version", "2.31.0"),
        ecosystem=kwargs.get("ecosystem", "pypi"),
        purl=kwargs.get("purl", "pkg:pypi/requests@2.31.0"),
        repository_url=kwargs.get("repository_url"),
    )


@pytest.mark.asyncio
async def test_pypi_enricher_success():
    component = _make_component()
    with respx.mock:
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json={
                "info": {"version": "2.31.0"},
                "releases": {
                    "2.0.0": [{"upload_time_iso_8601": "2014-01-01T00:00:00+00:00", "yanked": False}],
                    "2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00+00:00", "yanked": False}],
                }
            })
        )
        async with httpx.AsyncClient() as client:
            enricher = PyPIEnricher()
            result = await enricher.enrich(component, client)

    assert result.registry == "pypi"
    assert result.latest_version == "2.31.0"
    assert result.total_versions == 2
    assert result.first_published_days_ago is not None
    assert result.error is None


@pytest.mark.asyncio
async def test_pypi_enricher_not_found():
    component = _make_component(name="nonexistent-package-xyz")
    with respx.mock:
        respx.get("https://pypi.org/pypi/nonexistent-package-xyz/json").mock(
            return_value=httpx.Response(404)
        )
        async with httpx.AsyncClient() as client:
            enricher = PyPIEnricher()
            result = await enricher.enrich(component, client)

    assert result.error is not None
    assert "Not found" in result.error


@pytest.mark.asyncio
async def test_osv_enricher_with_vulns():
    component = _make_component()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(200, json={
                "vulns": [
                    {
                        "id": "GHSA-xyz-001",
                        "aliases": ["CVE-2023-12345"],
                        "severity": [{"type": "CVSS_V3", "score": "8.1"}],
                        "modified": "2023-10-01T00:00:00Z",
                    }
                ]
            })
        )
        async with httpx.AsyncClient() as client:
            enricher = OSVEnricher()
            result = await enricher.enrich(component, client)

    assert result.vuln_count_total == 1
    assert result.vuln_count_high == 1
    assert "CVE-2023-12345" in result.cve_ids
    assert result.error is None


@pytest.mark.asyncio
async def test_osv_enricher_no_vulns():
    component = _make_component()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(200, json={"vulns": []})
        )
        async with httpx.AsyncClient() as client:
            enricher = OSVEnricher()
            result = await enricher.enrich(component, client)

    assert result.vuln_count_total == 0
    assert result.cve_ids == []


@pytest.mark.asyncio
async def test_scorecard_enricher_success():
    component = _make_component(
        repository_url="https://github.com/psf/requests"
    )
    with respx.mock:
        respx.get("https://api.securityscorecards.dev/projects/github.com/psf/requests").mock(
            return_value=httpx.Response(200, json={
                "date": "2024-01-01",
                "score": 7.5,
                "checks": [
                    {"name": "Maintained", "score": 9},
                    {"name": "Vulnerabilities", "score": 8},
                ]
            })
        )
        async with httpx.AsyncClient() as client:
            enricher = ScorecardEnricher()
            result = await enricher.enrich(component, client)

    assert result.aggregate_score == 7.5
    assert result.checks["Maintained"] == 9.0
    assert result.error is None


@pytest.mark.asyncio
async def test_scorecard_no_github_repo():
    component = _make_component(repository_url=None, purl="pkg:pypi/requests@2.31.0")
    async with httpx.AsyncClient() as client:
        enricher = ScorecardEnricher()
        result = await enricher.enrich(component, client)

    assert result.error is not None
