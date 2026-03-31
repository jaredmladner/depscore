import asyncio
import re
from datetime import datetime, timedelta, timezone

import httpx

from depscore.enrichment.base import BaseEnricher
from depscore.exceptions import AuthenticationError, NotFoundError
from depscore.models.enrichment import GitHubData
from depscore.models.sbom import SBOMComponent

_GITHUB_URL_RE = re.compile(r"github\.com[/:]([^/]+)/([^/.\s]+)")


def _extract_owner_repo(component: SBOMComponent) -> tuple[str, str] | None:
    # Try repository_url first
    for url in filter(None, [component.repository_url]):
        m = _GITHUB_URL_RE.search(url)
        if m:
            return m.group(1), m.group(2).rstrip(".git")

    # Try PURL pkg:github/owner/repo
    if component.purl and component.purl.startswith("pkg:github/"):
        rest = component.purl[len("pkg:github/") :].split("@")[0]
        parts = rest.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]

    return None


class GitHubEnricher(BaseEnricher):
    BASE = "https://api.github.com"

    def __init__(self, token: str, timeout: float = 30.0, max_retries: int = 3) -> None:
        super().__init__(timeout=timeout, max_retries=max_retries)
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def enrich(
        self, component: SBOMComponent, client: httpx.AsyncClient
    ) -> GitHubData:
        coords = _extract_owner_repo(component)
        if not coords:
            return GitHubData(error="No GitHub repo URL found")

        owner, repo = coords
        full_name = f"{owner}/{repo}"

        try:
            (
                repo_data,
                community_data,
                contributors_data,
                commits_data,
                pr_data,
            ) = await asyncio.gather(
                self._get(
                    client, f"{self.BASE}/repos/{full_name}", headers=self.headers
                ),
                self._get(
                    client,
                    f"{self.BASE}/repos/{full_name}/community/profile",
                    headers=self.headers,
                ),
                self._get(
                    client,
                    f"{self.BASE}/repos/{full_name}/contributors",
                    headers=self.headers,
                    params={"per_page": "100", "anon": "true"},
                ),
                self._get(
                    client,
                    f"{self.BASE}/repos/{full_name}/commits",
                    headers=self.headers,
                    params={
                        "since": (
                            datetime.now(timezone.utc) - timedelta(days=90)
                        ).isoformat(),
                        "per_page": "100",
                    },
                ),
                self._get(
                    client,
                    f"{self.BASE}/repos/{full_name}/pulls",
                    headers=self.headers,
                    params={
                        "state": "open",
                        "sort": "created",
                        "direction": "asc",
                        "per_page": "100",
                    },
                ),
                return_exceptions=True,
            )
        except (AuthenticationError, NotFoundError) as exc:
            return GitHubData(repo_full_name=full_name, error=str(exc))

        errors: list[str] = []

        # Parse repo data
        stars = forks = open_issues = None
        default_branch = None
        org_name = None
        corporate_backed = None
        days_since_last_commit = None

        if isinstance(repo_data, dict):
            stars = repo_data.get("stargazers_count")
            forks = repo_data.get("forks_count")
            open_issues = repo_data.get("open_issues_count")
            default_branch = repo_data.get("default_branch", "main")
            org_name = (
                repo_data.get("organization", {}).get("login")
                if repo_data.get("organization")
                else None
            )
            corporate_backed = org_name is not None
            pushed_at = repo_data.get("pushed_at")
            if pushed_at:
                try:
                    dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    days_since_last_commit = (datetime.now(timezone.utc) - dt).days
                except ValueError:
                    pass
        elif isinstance(repo_data, Exception):
            errors.append(f"repo: {repo_data}")

        # Parse community profile
        has_security_md = None
        if isinstance(community_data, dict):
            files = community_data.get("files", {})
            has_security_md = files.get("security") is not None
        elif isinstance(community_data, Exception):
            errors.append(f"community: {community_data}")

        # Parse contributors
        total_contributors = None
        top_contributor_percent = None
        if isinstance(contributors_data, list):
            total_contributors = len(contributors_data)
            if total_contributors > 0:
                total_contributions = sum(
                    c.get("contributions", 0) for c in contributors_data
                )
                top_contributions = max(
                    (c.get("contributions", 0) for c in contributors_data), default=0
                )
                if total_contributions > 0:
                    top_contributor_percent = top_contributions / total_contributions
        elif isinstance(contributors_data, Exception):
            errors.append(f"contributors: {contributors_data}")

        # Parse commits (last 90 days)
        commits_last_90_days = None
        if isinstance(commits_data, list):
            commits_last_90_days = len(commits_data)
        elif isinstance(commits_data, Exception):
            errors.append(f"commits: {commits_data}")

        # Parse open PRs median age
        open_pr_age_days_median = None
        if isinstance(pr_data, list) and pr_data:
            now = datetime.now(timezone.utc)
            ages = []
            for pr in pr_data:
                created = pr.get("created_at", "")
                if created:
                    try:
                        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        ages.append((now - dt).days)
                    except ValueError:
                        pass
            if ages:
                ages.sort()
                mid = len(ages) // 2
                open_pr_age_days_median = float(ages[mid])
        elif isinstance(pr_data, Exception):
            errors.append(f"prs: {pr_data}")

        # Branch protection (best-effort, may 403)
        branch_protection_enabled = None
        signed_commits_required = None
        if default_branch:
            try:
                bp_data = await self._get(
                    client,
                    f"{self.BASE}/repos/{full_name}/branches/{default_branch}/protection",
                    headers=self.headers,
                )
                branch_protection_enabled = True
                signed_commits_required = bp_data.get("required_signatures", {}).get(
                    "enabled", False
                )
            except Exception as exc:
                errors.append(f"branch_protection: {exc}")

        return GitHubData(
            repo_full_name=full_name,
            stars=stars,
            forks=forks,
            open_issues=open_issues,
            days_since_last_commit=days_since_last_commit,
            commits_last_90_days=commits_last_90_days,
            total_contributors=total_contributors,
            top_contributor_percent=top_contributor_percent,
            has_security_md=has_security_md,
            branch_protection_enabled=branch_protection_enabled,
            signed_commits_required=signed_commits_required,
            open_pr_age_days_median=open_pr_age_days_median,
            corporate_backed=corporate_backed,
            org_name=org_name,
            default_branch=default_branch,
            error="; ".join(errors) if errors else None,
        )
