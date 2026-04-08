"""Tests for enrichers using mocked HTTP responses."""

import pytest
import respx
import httpx

from depscore.enrichment.github import GitHubEnricher
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
            return_value=httpx.Response(
                200,
                json={
                    "info": {"version": "2.31.0"},
                    "releases": {
                        "2.0.0": [
                            {
                                "upload_time_iso_8601": "2014-01-01T00:00:00+00:00",
                                "yanked": False,
                            }
                        ],
                        "2.31.0": [
                            {
                                "upload_time_iso_8601": "2023-05-22T00:00:00+00:00",
                                "yanked": False,
                            }
                        ],
                    },
                },
            )
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
            return_value=httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-xyz-001",
                            "aliases": ["CVE-2023-12345"],
                            "severity": [{"type": "CVSS_V3", "score": "8.1"}],
                            "modified": "2023-10-01T00:00:00Z",
                        }
                    ]
                },
            )
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
    component = _make_component(repository_url="https://github.com/psf/requests")
    with respx.mock:
        respx.get(
            "https://api.securityscorecards.dev/projects/github.com/psf/requests"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "date": "2024-01-01",
                    "score": 7.5,
                    "checks": [
                        {"name": "Maintained", "score": 9},
                        {"name": "Vulnerabilities", "score": 8},
                    ],
                },
            )
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


# ─── OSV CVE resolution speed ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_osv_enricher_cve_fix_resolution():
    """OSV enricher should compute pct_vulns_fixed and avg_days_to_fix."""
    component = _make_component()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-fixed-001",
                            "aliases": ["CVE-2023-00001"],
                            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                            "published": "2023-01-01T00:00:00Z",
                            "modified": "2023-01-11T00:00:00Z",  # 10-day fix
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "2.32.0"},
                                            ],
                                        }
                                    ]
                                }
                            ],
                        },
                        {
                            "id": "GHSA-fixed-002",
                            "aliases": ["CVE-2023-00002"],
                            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
                            "published": "2023-02-01T00:00:00Z",
                            "modified": "2023-02-21T00:00:00Z",  # 20-day fix
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "2.32.1"},
                                            ],
                                        }
                                    ]
                                }
                            ],
                        },
                    ]
                },
            )
        )
        async with httpx.AsyncClient() as client:
            enricher = OSVEnricher()
            result = await enricher.enrich(component, client)

    assert result.vuln_count_total == 2
    assert result.pct_vulns_fixed == 1.0  # both fixed
    assert result.avg_days_to_fix == 15.0  # (10 + 20) / 2
    assert result.unpatched_critical_count == 0
    assert result.error is None


@pytest.mark.asyncio
async def test_osv_enricher_unpatched_critical():
    """A critical CVE with no fix event should increment unpatched_critical_count."""
    component = _make_component()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-crit-001",
                            "aliases": ["CVE-2024-99999"],
                            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                            "published": "2024-01-01T00:00:00Z",
                            "modified": "2024-01-15T00:00:00Z",
                            # No 'fixed' event — still open
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [{"introduced": "0"}],
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                },
            )
        )
        async with httpx.AsyncClient() as client:
            enricher = OSVEnricher()
            result = await enricher.enrich(component, client)

    assert result.vuln_count_critical == 1
    assert result.unpatched_critical_count == 1
    assert result.pct_vulns_fixed == 0.0
    assert result.avg_days_to_fix is None


@pytest.mark.asyncio
async def test_osv_enricher_mixed_fixed_and_open():
    """Half fixed, half open → pct_vulns_fixed == 0.5."""
    component = _make_component()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-mix-001",
                            "severity": [{"type": "CVSS_V3", "score": "7.0"}],
                            "published": "2023-03-01T00:00:00Z",
                            "modified": "2023-03-31T00:00:00Z",
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "1.0.1"},
                                            ],
                                        }
                                    ]
                                }
                            ],
                        },
                        {
                            "id": "GHSA-mix-002",
                            "severity": [{"type": "CVSS_V3", "score": "6.0"}],
                            "published": "2023-04-01T00:00:00Z",
                            "modified": "2023-04-02T00:00:00Z",
                            # No fix
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [{"introduced": "0"}],
                                        }
                                    ]
                                }
                            ],
                        },
                    ]
                },
            )
        )
        async with httpx.AsyncClient() as client:
            enricher = OSVEnricher()
            result = await enricher.enrich(component, client)

    assert result.pct_vulns_fixed == 0.5
    assert result.avg_days_to_fix == 30.0


# ─── GitHub adversarial contributor detection ─────────────────────────────────

_GITHUB_REPO_RESPONSE = {
    "stargazers_count": 1000,
    "forks_count": 100,
    "open_issues_count": 10,
    "default_branch": "main",
    "pushed_at": "2024-01-01T00:00:00Z",
    "organization": None,
}

_GITHUB_COMMUNITY_RESPONSE = {
    "files": {"security": {"url": "https://github.com/test/repo/security/policy"}}
}

_GITHUB_CONTRIBUTORS_RESPONSE = [
    {"login": "alice", "contributions": 100},
    {"login": "bob", "contributions": 50},
]

_GITHUB_PR_RESPONSE: list = []


@pytest.mark.asyncio
async def test_github_enricher_adversarial_contributors_detected():
    """Commits with .cn email domains should be flagged as adversarial."""
    component = _make_component(
        repository_url="https://github.com/test/repo",
        purl="pkg:github/test/repo@1.0.0",
    )
    commits = [
        {
            "commit": {
                "author": {"email": "dev@example.cn", "name": "Dev"},
                "message": "fix bug",
            }
        },
        {
            "commit": {
                "author": {"email": "contributor@company.com", "name": "Contrib"},
                "message": "add feature",
            }
        },
        {
            "commit": {
                "author": {"email": "other@huawei.com", "name": "Other"},
                "message": "refactor",
            }
        },
    ]

    with respx.mock:
        respx.get("https://api.github.com/repos/test/repo").mock(
            return_value=httpx.Response(200, json=_GITHUB_REPO_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/community/profile").mock(
            return_value=httpx.Response(200, json=_GITHUB_COMMUNITY_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/contributors").mock(
            return_value=httpx.Response(200, json=_GITHUB_CONTRIBUTORS_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/commits").mock(
            return_value=httpx.Response(200, json=commits)
        )
        respx.get("https://api.github.com/repos/test/repo/pulls").mock(
            return_value=httpx.Response(200, json=_GITHUB_PR_RESPONSE)
        )
        respx.get(
            "https://api.github.com/repos/test/repo/branches/main/protection"
        ).mock(return_value=httpx.Response(403))

        async with httpx.AsyncClient() as client:
            enricher = GitHubEnricher(token="test-token")
            result = await enricher.enrich(component, client)

    # 2 out of 3 commit emails are adversarial (.cn, huawei.com)
    assert result.adversarial_contributor_pct is not None
    assert abs(result.adversarial_contributor_pct - 2 / 3) < 0.01
    assert len(result.adversarial_domains_found) >= 1


@pytest.mark.asyncio
async def test_github_enricher_no_adversarial_contributors():
    """Commits with only safe email domains → adversarial_contributor_pct == 0.0."""
    component = _make_component(
        repository_url="https://github.com/test/repo",
        purl="pkg:github/test/repo@1.0.0",
    )
    commits = [
        {
            "commit": {
                "author": {"email": "dev@gmail.com", "name": "Dev"},
                "message": "init",
            }
        },
        {
            "commit": {
                "author": {"email": "other@company.com", "name": "Other"},
                "message": "feat",
            }
        },
    ]

    with respx.mock:
        respx.get("https://api.github.com/repos/test/repo").mock(
            return_value=httpx.Response(200, json=_GITHUB_REPO_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/community/profile").mock(
            return_value=httpx.Response(200, json=_GITHUB_COMMUNITY_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/contributors").mock(
            return_value=httpx.Response(200, json=_GITHUB_CONTRIBUTORS_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/commits").mock(
            return_value=httpx.Response(200, json=commits)
        )
        respx.get("https://api.github.com/repos/test/repo/pulls").mock(
            return_value=httpx.Response(200, json=_GITHUB_PR_RESPONSE)
        )
        respx.get(
            "https://api.github.com/repos/test/repo/branches/main/protection"
        ).mock(return_value=httpx.Response(403))

        async with httpx.AsyncClient() as client:
            enricher = GitHubEnricher(token="test-token")
            result = await enricher.enrich(component, client)

    assert result.adversarial_contributor_pct == 0.0
    assert result.adversarial_domains_found == []


@pytest.mark.asyncio
async def test_github_enricher_ru_domain_flagged():
    """Commits with .ru email domains should be detected."""
    component = _make_component(
        repository_url="https://github.com/test/repo",
        purl="pkg:github/test/repo@1.0.0",
    )
    commits = [
        {
            "commit": {
                "author": {"email": "maintainer@mail.ru", "name": "Maintainer"},
                "message": "security fix",
            }
        },
    ]

    with respx.mock:
        respx.get("https://api.github.com/repos/test/repo").mock(
            return_value=httpx.Response(200, json=_GITHUB_REPO_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/community/profile").mock(
            return_value=httpx.Response(200, json=_GITHUB_COMMUNITY_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/contributors").mock(
            return_value=httpx.Response(200, json=_GITHUB_CONTRIBUTORS_RESPONSE)
        )
        respx.get("https://api.github.com/repos/test/repo/commits").mock(
            return_value=httpx.Response(200, json=commits)
        )
        respx.get("https://api.github.com/repos/test/repo/pulls").mock(
            return_value=httpx.Response(200, json=_GITHUB_PR_RESPONSE)
        )
        respx.get(
            "https://api.github.com/repos/test/repo/branches/main/protection"
        ).mock(return_value=httpx.Response(403))

        async with httpx.AsyncClient() as client:
            enricher = GitHubEnricher(token="test-token")
            result = await enricher.enrich(component, client)

    assert result.adversarial_contributor_pct == 1.0
    assert ".ru" in result.adversarial_domains_found
