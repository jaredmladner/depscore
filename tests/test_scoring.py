"""Tests for the rules-based scoring layer."""

import pytest

from depscore.models.dependency import EnrichedDependency
from depscore.models.enrichment import GitHubData, LibrariesIOData, OSVData, RegistryData, ScorecardData
from depscore.models.sbom import SBOMComponent
from depscore.scoring import rules as rules_mod
from depscore.scoring.weights import score_to_grade


def _make_dep(**kwargs) -> EnrichedDependency:
    comp = SBOMComponent(
        name=kwargs.pop("name", "test-pkg"),
        version=kwargs.pop("version", "1.0.0"),
        ecosystem=kwargs.pop("ecosystem", "pypi"),
        purl=kwargs.pop("purl", "pkg:pypi/test-pkg@1.0.0"),
    )
    return EnrichedDependency(component=comp, **kwargs)


# ─── Maturity ─────────────────────────────────────────────────────────────────

def test_maturity_stable_well_adopted():
    dep = _make_dep(
        version="3.0.0",
        registry=RegistryData(
            registry="pypi",
            first_published_days_ago=2000,
            total_versions=80,
            weekly_downloads=5_000_000,
            latest_published_days_ago=10,
        ),
    )
    score, confidence, _ = rules_mod.score_maturity(dep)
    assert score >= 80
    assert confidence > 0.5


def test_maturity_alpha_version():
    dep = _make_dep(version="0.1.0alpha1")
    score, confidence, _ = rules_mod.score_maturity(dep)
    assert score < 50


def test_maturity_brand_new():
    dep = _make_dep(
        version="0.0.1",
        registry=RegistryData(
            registry="pypi",
            first_published_days_ago=10,
            total_versions=1,
            weekly_downloads=50,
        ),
    )
    score, _, _ = rules_mod.score_maturity(dep)
    assert score < 40


# ─── Maintainability ─────────────────────────────────────────────────────────

def test_maintainability_active():
    dep = _make_dep(
        github=GitHubData(
            days_since_last_commit=3,
            commits_last_90_days=60,
            open_pr_age_days_median=5.0,
            top_contributor_percent=0.10,
        )
    )
    score, _, _ = rules_mod.score_maintainability(dep)
    assert score >= 80


def test_maintainability_abandoned():
    dep = _make_dep(
        github=GitHubData(
            days_since_last_commit=500,
            commits_last_90_days=0,
            open_pr_age_days_median=200.0,
            top_contributor_percent=0.95,
        )
    )
    score, _, _ = rules_mod.score_maintainability(dep)
    assert score < 30


def test_maintainability_no_github_data():
    dep = _make_dep()
    score, confidence, _ = rules_mod.score_maintainability(dep)
    assert score == 50.0
    assert confidence == 0.0


# ─── Security Posture ─────────────────────────────────────────────────────────

def test_security_no_vulns():
    dep = _make_dep(
        osv=OSVData(vuln_count_total=0),
        github=GitHubData(
            has_security_md=True,
            branch_protection_enabled=True,
            signed_commits_required=True,
        ),
    )
    score, _, _ = rules_mod.score_security_posture(dep)
    assert score >= 80


def test_security_critical_vuln():
    dep = _make_dep(
        osv=OSVData(vuln_count_total=2, vuln_count_critical=2),
    )
    score, _, _ = rules_mod.score_security_posture(dep)
    assert score < 30


def test_security_high_vulns():
    dep = _make_dep(
        osv=OSVData(vuln_count_total=3, vuln_count_high=3),
    )
    score, _, _ = rules_mod.score_security_posture(dep)
    assert score < 50


# ─── Community Health ─────────────────────────────────────────────────────────

def test_community_diverse():
    dep = _make_dep(
        github=GitHubData(total_contributors=200, top_contributor_percent=0.05),
        libraries_io=LibrariesIOData(sourcerank=25),
    )
    score, _, _ = rules_mod.score_community_health(dep)
    assert score >= 80


def test_community_solo():
    dep = _make_dep(
        github=GitHubData(total_contributors=1, top_contributor_percent=1.0),
    )
    score, _, _ = rules_mod.score_community_health(dep)
    assert score < 20


# ─── Grade thresholds ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected_grade", [
    (95.0, "A"), (80.0, "A"), (79.9, "B"), (65.0, "B"),
    (64.9, "C"), (50.0, "C"), (49.9, "D"), (35.0, "D"),
    (34.9, "F"), (0.0, "F"),
])
def test_grade_thresholds(score: float, expected_grade: str) -> None:
    assert score_to_grade(score) == expected_grade
