"""Tests for the rules-based scoring layer."""

import pytest

from depscore.models.dependency import EnrichedDependency
from depscore.models.enrichment import (
    GitHubData,
    LibrariesIOData,
    OSVData,
    RegistryData,
)
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
        osv=OSVData(
            vuln_count_total=2,
            vuln_count_critical=2,
            unpatched_critical_count=2,
        ),
    )
    score, _, _ = rules_mod.score_security_posture(dep)
    assert score < 30


def test_security_high_vulns():
    dep = _make_dep(
        osv=OSVData(vuln_count_total=3, vuln_count_high=3, unpatched_critical_count=0),
    )
    score, _, _ = rules_mod.score_security_posture(dep)
    assert score < 70


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


# ─── CVE Resolution Speed (unit) ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "pct_fixed,min_score,max_score",
    [
        (1.0, 90, 100),  # all fixed → high score
        (0.95, 90, 100),  # at threshold
        (0.80, 75, 85),
        (0.60, 55, 65),
        (0.40, 35, 45),
        (0.20, 10, 20),  # low fix rate → low score
        (None, None, None),
    ],
)
def test_cve_fix_rate_score(pct_fixed, min_score, max_score):
    result = rules_mod._cve_fix_rate_score(pct_fixed)
    if pct_fixed is None:
        assert result is None
    else:
        assert min_score <= result <= max_score


@pytest.mark.parametrize(
    "avg_days,min_score,max_score",
    [
        (3, 95, 100),  # fixed in < 1 week → excellent
        (7, 95, 100),  # exactly 7 days
        (15, 80, 90),
        (60, 60, 70),
        (120, 35, 45),
        (200, 15, 25),
        (400, 0, 10),  # > 365 days → 5.0
        (None, None, None),
    ],
)
def test_cve_resolution_speed_score(avg_days, min_score, max_score):
    result = rules_mod._cve_resolution_speed_score(avg_days)
    if avg_days is None:
        assert result is None
    else:
        assert min_score <= result <= max_score


@pytest.mark.parametrize(
    "count,expected",
    [
        (0, 100.0),
        (1, 20.0),
        (2, 10.0),
        (3, 0.0),
        (10, 0.0),  # capped at 0
    ],
)
def test_unpatched_critical_score(count, expected):
    assert rules_mod._unpatched_critical_score(count) == expected


# ─── CVE Resolution Speed (integration) ──────────────────────────────────────


def test_security_fast_cve_fix_rate_boosts_score():
    """High fix rate + fast resolution should push security score above baseline."""
    dep_good = _make_dep(
        osv=OSVData(
            vuln_count_total=5,
            vuln_count_high=5,
            pct_vulns_fixed=1.0,
            avg_days_to_fix=5.0,
            unpatched_critical_count=0,
        ),
        github=GitHubData(has_security_md=True, branch_protection_enabled=True),
    )
    dep_bad = _make_dep(
        osv=OSVData(
            vuln_count_total=5,
            vuln_count_high=5,
            pct_vulns_fixed=0.20,
            avg_days_to_fix=400.0,
            unpatched_critical_count=0,
        ),
    )
    score_good, _, _ = rules_mod.score_security_posture(dep_good)
    score_bad, _, _ = rules_mod.score_security_posture(dep_bad)
    assert score_good > score_bad


def test_security_unpatched_critical_tanks_score():
    """Unpatched critical CVEs should significantly lower the security score."""
    dep = _make_dep(
        osv=OSVData(
            vuln_count_total=2,
            vuln_count_critical=2,
            pct_vulns_fixed=0.0,
            avg_days_to_fix=None,
            unpatched_critical_count=2,
        ),
        github=GitHubData(has_security_md=True, branch_protection_enabled=True),
    )
    score, _, signals = rules_mod.score_security_posture(dep)
    assert score < 35
    assert signals["unpatched_critical_count"] == 2


# ─── Adversarial Contributors (unit) ─────────────────────────────────────────


@pytest.mark.parametrize(
    "pct,max_score",
    [
        (0.0, 100),  # zero adversarial → neutral
        (0.03, 65),  # small presence → flagged
        (0.10, 40),  # moderate
        (0.20, 20),  # high
        (0.35, 10),  # majority
        (None, None),
    ],
)
def test_adversarial_contributor_score(pct, max_score):
    result = rules_mod._adversarial_contributor_score(pct)
    if pct is None:
        assert result is None
    elif pct == 0.0:
        assert result == 100.0
    else:
        assert result <= max_score


# ─── Adversarial Contributors (integration) ──────────────────────────────────


def test_community_adversarial_pct_lowers_score():
    """A project with adversarial contributors should score lower than one without."""
    dep_clean = _make_dep(
        github=GitHubData(
            total_contributors=50,
            top_contributor_percent=0.10,
            adversarial_contributor_pct=0.0,
            adversarial_domains_found=[],
        ),
    )
    dep_risky = _make_dep(
        github=GitHubData(
            total_contributors=50,
            top_contributor_percent=0.10,
            adversarial_contributor_pct=0.20,
            adversarial_domains_found=[".cn"],
        ),
    )
    score_clean, _, _ = rules_mod.score_community_health(dep_clean)
    score_risky, _, _ = rules_mod.score_community_health(dep_risky)
    assert score_clean > score_risky


def test_community_adversarial_zero_pct_no_penalty():
    """Explicitly zero adversarial pct should not penalise community score."""
    dep = _make_dep(
        github=GitHubData(
            total_contributors=80,
            top_contributor_percent=0.08,
            adversarial_contributor_pct=0.0,
            adversarial_domains_found=[],
        ),
        libraries_io=LibrariesIOData(sourcerank=22),
    )
    score, _, signals = rules_mod.score_community_health(dep)
    assert score >= 75
    assert signals["adversarial_contributor_pct"] == 0.0


def test_community_adversarial_signals_present_in_signals_dict():
    dep = _make_dep(
        github=GitHubData(
            adversarial_contributor_pct=0.12,
            adversarial_domains_found=[".ru", ".cn"],
        ),
    )
    _, _, signals = rules_mod.score_community_health(dep)
    assert signals["adversarial_contributor_pct"] == 0.12
    assert ".ru" in signals["adversarial_domains_found"]
    assert ".cn" in signals["adversarial_domains_found"]


# ─── Grade thresholds ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "score,expected_grade",
    [
        (95.0, "A"),
        (80.0, "A"),
        (79.9, "B"),
        (65.0, "B"),
        (64.9, "C"),
        (50.0, "C"),
        (49.9, "D"),
        (35.0, "D"),
        (34.9, "F"),
        (0.0, "F"),
    ],
)
def test_grade_thresholds(score: float, expected_grade: str) -> None:
    assert score_to_grade(score) == expected_grade
