from pydantic import BaseModel


class GitHubData(BaseModel):
    repo_full_name: str | None = None
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None
    days_since_last_commit: int | None = None
    commits_last_90_days: int | None = None
    total_contributors: int | None = None
    top_contributor_percent: float | None = None
    has_security_md: bool | None = None
    branch_protection_enabled: bool | None = None
    signed_commits_required: bool | None = None
    open_pr_age_days_median: float | None = None
    corporate_backed: bool | None = None
    org_name: str | None = None
    default_branch: str | None = None
    error: str | None = None


class ScorecardData(BaseModel):
    repo: str | None = None
    date: str | None = None
    aggregate_score: float | None = None  # 0-10
    checks: dict[str, float] = {}
    error: str | None = None


class OSVData(BaseModel):
    vuln_count_total: int = 0
    vuln_count_critical: int = 0
    vuln_count_high: int = 0
    vuln_count_medium: int = 0
    vuln_count_low: int = 0
    most_recent_vuln_days_ago: int | None = None
    cve_ids: list[str] = []
    error: str | None = None


class LibrariesIOData(BaseModel):
    dependent_repos_count: int | None = None
    dependent_packages_count: int | None = None
    latest_release_days_ago: int | None = None
    release_count: int | None = None
    first_publish_days_ago: int | None = None
    sourcerank: int | None = None
    error: str | None = None


class RegistryData(BaseModel):
    registry: str  # pypi, npm, maven, nuget
    latest_version: str | None = None
    total_versions: int | None = None
    first_published_days_ago: int | None = None
    latest_published_days_ago: int | None = None
    weekly_downloads: int | None = None
    is_prerelease: bool | None = None
    error: str | None = None
