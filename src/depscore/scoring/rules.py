"""Deterministic rules-based scoring layer.

Each dimension score is computed as a weighted average of individual signals.
Signals with None values are excluded from the average, and the confidence
reflects what fraction of expected signals were available.
"""

from depscore.models.dependency import EnrichedDependency


def _weighted_avg(
    signal_scores: list[tuple[float | None, float]],
) -> tuple[float, float]:
    """Compute (score, confidence) from [(value_or_None, weight), ...].

    Returns (score 0-100, confidence 0-1).
    """
    total_weight = sum(w for _, w in signal_scores)
    available_weight = sum(w for v, w in signal_scores if v is not None)
    if available_weight == 0:
        return 50.0, 0.0
    score = sum(v * w for v, w in signal_scores if v is not None) / available_weight
    confidence = available_weight / total_weight
    return round(score, 2), round(confidence, 3)


# ─── Maturity ────────────────────────────────────────────────────────────────


def _version_maturity(version: str | None) -> float | None:
    if not version:
        return None
    v = version.lower()
    if any(s in v for s in ("alpha", "a0", "a1", "beta", "b0", "b1", "dev", "rc")):
        return 15.0
    if v.startswith("0."):
        return 35.0
    parts = v.split(".")
    try:
        major = int(parts[0].lstrip("v"))
        if major >= 2:
            return 90.0
        return 70.0
    except (ValueError, IndexError):
        return 50.0


def _age_maturity(first_published_days_ago: int | None) -> float | None:
    if first_published_days_ago is None:
        return None
    if first_published_days_ago < 90:
        return 10.0
    if first_published_days_ago < 365:
        return 40.0
    if first_published_days_ago < 730:
        return 65.0
    if first_published_days_ago < 1825:
        return 80.0
    return 95.0


def _release_count_maturity(count: int | None) -> float | None:
    if count is None:
        return None
    if count < 3:
        return 20.0
    if count < 10:
        return 50.0
    if count < 30:
        return 70.0
    if count < 100:
        return 85.0
    return 95.0


def _downloads_maturity(weekly: int | None) -> float | None:
    if weekly is None:
        return None
    if weekly < 1_000:
        return 20.0
    if weekly < 10_000:
        return 45.0
    if weekly < 100_000:
        return 65.0
    if weekly < 1_000_000:
        return 80.0
    return 95.0


# ─── Maintainability ─────────────────────────────────────────────────────────


def _recency_score(days: int | None) -> float | None:
    if days is None:
        return None
    if days <= 7:
        return 100.0
    if days <= 30:
        return 85.0
    if days <= 90:
        return 65.0
    if days <= 180:
        return 40.0
    if days <= 365:
        return 20.0
    return 5.0


def _commit_cadence_score(commits_90d: int | None) -> float | None:
    if commits_90d is None:
        return None
    if commits_90d >= 50:
        return 95.0
    if commits_90d >= 20:
        return 80.0
    if commits_90d >= 5:
        return 60.0
    if commits_90d >= 1:
        return 35.0
    return 10.0


def _pr_age_score(median_days: float | None) -> float | None:
    if median_days is None:
        return None
    if median_days <= 3:
        return 95.0
    if median_days <= 14:
        return 80.0
    if median_days <= 30:
        return 60.0
    if median_days <= 90:
        return 35.0
    return 15.0


def _bus_factor_score(top_pct: float | None) -> float | None:
    """Lower concentration of contributions = better."""
    if top_pct is None:
        return None
    if top_pct <= 0.15:
        return 95.0
    if top_pct <= 0.30:
        return 75.0
    if top_pct <= 0.50:
        return 50.0
    if top_pct <= 0.75:
        return 25.0
    return 10.0


# ─── Security Posture ─────────────────────────────────────────────────────────


def _vuln_score(osv) -> float | None:
    if osv is None:
        return None
    critical = osv.vuln_count_critical
    high = osv.vuln_count_high
    med = osv.vuln_count_medium
    if critical >= 1:
        return max(0.0, 30.0 - (critical * 10))
    if high >= 3:
        return 35.0
    if high >= 1:
        return 50.0
    if med >= 5:
        return 60.0
    if med >= 1:
        return 75.0
    return 100.0


def _security_md_score(has: bool | None) -> float | None:
    if has is None:
        return None
    return 85.0 if has else 30.0


def _branch_protection_score(enabled: bool | None) -> float | None:
    if enabled is None:
        return None
    return 80.0 if enabled else 20.0


def _signed_commits_score(required: bool | None) -> float | None:
    if required is None:
        return None
    return 90.0 if required else 40.0


def _scorecard_security_score(checks: dict | None) -> float | None:
    if not checks:
        return None
    relevant = [
        "Vulnerabilities",
        "Binary-Artifacts",
        "Dangerous-Workflow",
        "Token-Permissions",
    ]
    vals = [checks[k] * 10 for k in relevant if k in checks]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


# ─── CVE Resolution Speed ────────────────────────────────────────────────────


def _cve_fix_rate_score(pct_fixed: float | None) -> float | None:
    """Score based on what fraction of historical CVEs have a fix available."""
    if pct_fixed is None:
        return None
    if pct_fixed >= 0.95:
        return 95.0
    if pct_fixed >= 0.80:
        return 80.0
    if pct_fixed >= 0.60:
        return 60.0
    if pct_fixed >= 0.40:
        return 40.0
    return 15.0


def _cve_resolution_speed_score(avg_days: float | None) -> float | None:
    """Score based on average days from CVE disclosure to fix (lower = better)."""
    if avg_days is None:
        return None
    if avg_days <= 7:
        return 100.0
    if avg_days <= 30:
        return 85.0
    if avg_days <= 90:
        return 65.0
    if avg_days <= 180:
        return 40.0
    if avg_days <= 365:
        return 20.0
    return 5.0


def _unpatched_critical_score(count: int) -> float:
    """Heavy penalty for critical CVEs with no fix available."""
    if count == 0:
        return 100.0
    if count == 1:
        return 20.0
    return max(0.0, 20.0 - (count - 1) * 10)


# ─── Community Health ─────────────────────────────────────────────────────────


def _contributor_count_score(count: int | None) -> float | None:
    if count is None:
        return None
    if count >= 100:
        return 95.0
    if count >= 30:
        return 80.0
    if count >= 10:
        return 60.0
    if count >= 3:
        return 35.0
    return 10.0


def _sourcerank_score(rank: int | None) -> float | None:
    if rank is None:
        return None
    # Libraries.io SourceRank is typically 0-30
    return min(100.0, (rank / 30) * 100)


def _adversarial_contributor_score(pct: float | None) -> float | None:
    """
    Penalise based on fraction of recent commits from adversarial-nation domains.
    Relevant for DoD/federal supply chain risk (EO 13873, NDAA 2019/2023).
    0 adversarial commits → neutral (100); any presence → graduated penalty.
    """
    if pct is None:
        return None
    if pct == 0.0:
        return 100.0
    if pct <= 0.05:
        return 60.0  # small presence — flag but don't catastrophise
    if pct <= 0.15:
        return 35.0
    if pct <= 0.30:
        return 15.0
    return 5.0  # majority of recent commits from adversarial domains


def _scorecard_community_score(checks: dict | None) -> float | None:
    if not checks:
        return None
    relevant = ["Maintained", "Code-Review", "Contributors"]
    vals = [checks[k] * 10 for k in relevant if k in checks]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


# ─── Public API ───────────────────────────────────────────────────────────────


def score_maturity(dep: EnrichedDependency) -> tuple[float, float, dict]:
    registry = dep.registry
    lib = dep.libraries_io
    signals: dict = {}

    version_score = _version_maturity(dep.component.version)
    age_score = _age_maturity(
        (registry.first_published_days_ago if registry else None)
        or (lib.first_publish_days_ago if lib else None)
    )
    release_score = _release_count_maturity(
        (registry.total_versions if registry else None)
        or (lib.release_count if lib else None)
    )
    download_score = _downloads_maturity(
        registry.weekly_downloads if registry else None
    )

    signals["version_score"] = version_score
    signals["age_score"] = age_score
    signals["release_count_score"] = release_score
    signals["downloads_score"] = download_score
    signals["version"] = dep.component.version
    signals["first_published_days_ago"] = age_score and (
        registry.first_published_days_ago
        if registry
        else (lib.first_publish_days_ago if lib else None)
    )

    score, confidence = _weighted_avg(
        [
            (version_score, 2.0),
            (age_score, 2.0),
            (release_score, 1.5),
            (download_score, 1.0),
        ]
    )
    return score, confidence, signals


def score_maintainability(dep: EnrichedDependency) -> tuple[float, float, dict]:
    gh = dep.github
    signals: dict = {}

    recency = _recency_score(gh.days_since_last_commit if gh else None)
    cadence = _commit_cadence_score(gh.commits_last_90_days if gh else None)
    pr_age = _pr_age_score(gh.open_pr_age_days_median if gh else None)
    bus = _bus_factor_score(gh.top_contributor_percent if gh else None)

    signals["days_since_last_commit"] = gh.days_since_last_commit if gh else None
    signals["commits_last_90_days"] = gh.commits_last_90_days if gh else None
    signals["open_pr_age_days_median"] = gh.open_pr_age_days_median if gh else None
    signals["top_contributor_percent"] = gh.top_contributor_percent if gh else None

    score, confidence = _weighted_avg(
        [
            (recency, 3.0),
            (cadence, 2.5),
            (pr_age, 1.5),
            (bus, 2.0),
        ]
    )
    return score, confidence, signals


def score_security_posture(dep: EnrichedDependency) -> tuple[float, float, dict]:
    gh = dep.github
    osv = dep.osv
    scorecard = dep.scorecard
    signals: dict = {}

    vuln = _vuln_score(osv)
    sec_md = _security_md_score(gh.has_security_md if gh else None)
    bp = _branch_protection_score(gh.branch_protection_enabled if gh else None)
    signed = _signed_commits_score(gh.signed_commits_required if gh else None)
    sc_sec = _scorecard_security_score(scorecard.checks if scorecard else None)

    # CVE resolution speed signals
    fix_rate = _cve_fix_rate_score(osv.pct_vulns_fixed if osv else None)
    resolution_speed = _cve_resolution_speed_score(osv.avg_days_to_fix if osv else None)
    unpatched_crit = (
        _unpatched_critical_score(osv.unpatched_critical_count) if osv else None
    )

    signals["vuln_count_critical"] = osv.vuln_count_critical if osv else None
    signals["vuln_count_high"] = osv.vuln_count_high if osv else None
    signals["pct_vulns_fixed"] = osv.pct_vulns_fixed if osv else None
    signals["avg_days_to_fix"] = osv.avg_days_to_fix if osv else None
    signals["unpatched_critical_count"] = osv.unpatched_critical_count if osv else None
    signals["has_security_md"] = gh.has_security_md if gh else None
    signals["branch_protection_enabled"] = gh.branch_protection_enabled if gh else None
    signals["signed_commits_required"] = gh.signed_commits_required if gh else None
    signals["scorecard_aggregate"] = scorecard.aggregate_score if scorecard else None

    score, confidence = _weighted_avg(
        [
            (vuln, 4.0),
            (unpatched_crit, 3.0),  # unpatched criticals are an independent hard signal
            (fix_rate, 2.0),
            (resolution_speed, 1.5),
            (sec_md, 1.5),
            (bp, 1.5),
            (signed, 1.0),
            (sc_sec, 2.0),
        ]
    )
    return score, confidence, signals


def score_community_health(dep: EnrichedDependency) -> tuple[float, float, dict]:
    gh = dep.github
    lib = dep.libraries_io
    scorecard = dep.scorecard
    signals: dict = {}

    contributor_count = _contributor_count_score(gh.total_contributors if gh else None)
    bus = _bus_factor_score(gh.top_contributor_percent if gh else None)
    sourcerank = _sourcerank_score(lib.sourcerank if lib else None)
    sc_comm = _scorecard_community_score(scorecard.checks if scorecard else None)

    # Adversarial contributor signal (DoD/federal supply chain risk)
    adversarial = _adversarial_contributor_score(
        gh.adversarial_contributor_pct if gh else None
    )

    signals["total_contributors"] = gh.total_contributors if gh else None
    signals["top_contributor_percent"] = gh.top_contributor_percent if gh else None
    signals["sourcerank"] = lib.sourcerank if lib else None
    signals["org_name"] = gh.org_name if gh else None
    signals["corporate_backed"] = gh.corporate_backed if gh else None
    signals["adversarial_contributor_pct"] = (
        gh.adversarial_contributor_pct if gh else None
    )
    signals["adversarial_domains_found"] = gh.adversarial_domains_found if gh else []

    score, confidence = _weighted_avg(
        [
            (contributor_count, 2.5),
            (bus, 2.0),
            (sourcerank, 1.5),
            (sc_comm, 2.0),
            (adversarial, 3.0),  # weighted heavily for federal/DoD relevance
        ]
    )
    return score, confidence, signals
