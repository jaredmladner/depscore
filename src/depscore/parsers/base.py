import re
from abc import ABC, abstractmethod
from pathlib import Path

from depscore.models.sbom import ParsedSBOM, SBOMComponent

# Maps PURL scheme to ecosystem name
PURL_ECOSYSTEM_MAP = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "nuget": "nuget",
    "cargo": "cargo",
    "gem": "gem",
    "golang": "golang",
    "github": "github",
    "composer": "composer",
}

_PURL_RE = re.compile(r"^pkg:([^/]+)/")


def ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl:
        return None
    m = _PURL_RE.match(purl)
    if not m:
        return None
    return PURL_ECOSYSTEM_MAP.get(m.group(1), m.group(1))


def repo_url_from_purl(purl: str | None) -> str | None:
    """Best-effort extraction of GitHub URL from a github-type PURL."""
    if not purl or not purl.startswith("pkg:github/"):
        return None
    # pkg:github/owner/repo@version
    rest = purl[len("pkg:github/") :]
    parts = rest.split("@")[0].split("/")
    if len(parts) >= 2:
        return f"https://github.com/{parts[0]}/{parts[1]}"
    return None


class SBOMParser(ABC):
    @abstractmethod
    def parse(self, path: Path) -> ParsedSBOM: ...

    def _normalize_component(
        self,
        name: str,
        version: str | None,
        purl: str | None,
        repository_url: str | None,
        license_str: str | None,
    ) -> SBOMComponent:
        ecosystem = ecosystem_from_purl(purl)
        repo = repository_url or repo_url_from_purl(purl)
        return SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            ecosystem=ecosystem,
            repository_url=repo,
            license=license_str,
        )
