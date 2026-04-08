"""Ignore-file support for depscore.

Reads a .depscoreignore file and matches SBOMComponents against its rules.

Pattern syntax (one rule per line, # starts a comment):
  requests                          # exact name match
  internal-*                        # name glob (fnmatch)
  com.mycompany.*                   # name glob
  pkg:maven/com.mycompany/          # PURL prefix
  pkg:pypi/private-tool@1.0.0       # exact PURL
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from depscore.models.sbom import SBOMComponent

DEFAULT_IGNORE_FILENAME = ".depscoreignore"

# Lines that look like a PURL (start with pkg:)
_PURL_PREFIX_RE = re.compile(r"^pkg:[a-zA-Z0-9+\-.]+/")


def _is_purl_pattern(pattern: str) -> bool:
    return bool(_PURL_PREFIX_RE.match(pattern))


def load_ignore_patterns(ignore_file: Path | None) -> list[str]:
    """Return non-empty, non-comment lines from the ignore file.

    Returns an empty list if the file does not exist or is None.
    """
    if ignore_file is None:
        ignore_file = Path(DEFAULT_IGNORE_FILENAME)
    if not ignore_file.exists():
        return []
    lines: list[str] = []
    for raw in ignore_file.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def is_ignored(component: SBOMComponent, patterns: list[str]) -> tuple[bool, str]:
    """Return (True, matched_pattern) if the component matches any ignore rule."""
    name = component.name or ""
    purl = component.purl or ""

    for pattern in patterns:
        if _is_purl_pattern(pattern):
            # Exact PURL match or PURL prefix (pattern ends without @version suffix)
            if pattern.endswith("/"):
                # prefix match: pkg:maven/com.mycompany/
                if purl.startswith(pattern):
                    return True, pattern
            else:
                # exact PURL match (may include version)
                if purl == pattern:
                    return True, pattern
                # also support glob on full PURL
                if fnmatch.fnmatchcase(purl, pattern):
                    return True, pattern
        else:
            # Name-based: exact or glob
            if fnmatch.fnmatchcase(name, pattern):
                return True, pattern
            # Case-insensitive fallback for name globs
            if fnmatch.fnmatchcase(name.lower(), pattern.lower()):
                return True, pattern

    return False, ""


def filter_components(
    components: list[SBOMComponent],
    patterns: list[str],
) -> tuple[list[SBOMComponent], list[dict]]:
    """Split components into (active, ignored).

    Returns:
        active: components that will be enriched and scored
        ignored: list of dicts with name/purl/matched_pattern for the report
    """
    active: list[SBOMComponent] = []
    ignored: list[dict] = []
    for comp in components:
        matched, pattern = is_ignored(comp, patterns)
        if matched:
            ignored.append(
                {
                    "name": comp.name,
                    "version": comp.version,
                    "purl": comp.purl,
                    "matched_pattern": pattern,
                }
            )
        else:
            active.append(comp)
    return active, ignored
