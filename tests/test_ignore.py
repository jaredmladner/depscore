"""Tests for .depscoreignore parsing and component filtering."""

import textwrap
from pathlib import Path

import pytest

from depscore.ignore import filter_components, is_ignored, load_ignore_patterns
from depscore.models.sbom import SBOMComponent


def _comp(name: str, purl: str = "", version: str = "1.0.0") -> SBOMComponent:
    return SBOMComponent(
        name=name,
        version=version,
        ecosystem="pypi",
        purl=purl or f"pkg:pypi/{name}@{version}",
    )


# ─── load_ignore_patterns ────────────────────────────────────────────────────


def test_load_missing_file_returns_empty(tmp_path):
    result = load_ignore_patterns(tmp_path / "nonexistent.ignore")
    assert result == []


def test_load_strips_comments_and_blanks(tmp_path):
    f = tmp_path / ".depscoreignore"
    f.write_text(
        textwrap.dedent("""\
        # comment
        requests
        # another comment

        boto3
        """)
    )
    patterns = load_ignore_patterns(f)
    assert patterns == ["requests", "boto3"]


def test_load_inline_comment_stripped(tmp_path):
    f = tmp_path / ".depscoreignore"
    f.write_text("internal-lib  # our private package\n")
    patterns = load_ignore_patterns(f)
    assert patterns == ["internal-lib"]


def test_load_none_checks_default_filename(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # No .depscoreignore in CWD → empty
    assert load_ignore_patterns(None) == []

    (tmp_path / ".depscoreignore").write_text("mylib\n")
    assert load_ignore_patterns(None) == ["mylib"]


# ─── is_ignored — name matching ───────────────────────────────────────────────


def test_exact_name_match():
    comp = _comp("requests")
    matched, pat = is_ignored(comp, ["requests"])
    assert matched is True
    assert pat == "requests"


def test_exact_name_no_match():
    comp = _comp("requests")
    matched, _ = is_ignored(comp, ["boto3"])
    assert matched is False


def test_name_glob_wildcard():
    comp = _comp("internal-auth")
    matched, pat = is_ignored(comp, ["internal-*"])
    assert matched is True
    assert pat == "internal-*"


def test_name_glob_dot_star():
    comp = _comp("com.mycompany.auth", purl="pkg:maven/com.mycompany/auth@1.0.0")
    matched, _ = is_ignored(comp, ["com.mycompany.*"])
    assert matched is True


def test_name_glob_no_match():
    comp = _comp("requests")
    matched, _ = is_ignored(comp, ["internal-*"])
    assert matched is False


# ─── is_ignored — PURL matching ──────────────────────────────────────────────


def test_exact_purl_match():
    comp = _comp("requests", purl="pkg:pypi/requests@2.31.0", version="2.31.0")
    matched, pat = is_ignored(comp, ["pkg:pypi/requests@2.31.0"])
    assert matched is True
    assert pat == "pkg:pypi/requests@2.31.0"


def test_purl_prefix_match():
    comp = _comp("auth", purl="pkg:maven/com.mycompany/auth@1.0.0", version="1.0.0")
    matched, pat = is_ignored(comp, ["pkg:maven/com.mycompany/"])
    assert matched is True
    assert pat == "pkg:maven/com.mycompany/"


def test_purl_prefix_no_match_different_group():
    comp = _comp("auth", purl="pkg:maven/org.apache/auth@1.0.0")
    matched, _ = is_ignored(comp, ["pkg:maven/com.mycompany/"])
    assert matched is False


def test_purl_glob():
    comp = _comp("requests", purl="pkg:pypi/requests@2.31.0")
    matched, _ = is_ignored(comp, ["pkg:pypi/requests@*"])
    assert matched is True


# ─── filter_components ────────────────────────────────────────────────────────


def test_filter_splits_correctly():
    components = [
        _comp("requests"),
        _comp("internal-auth"),
        _comp("boto3"),
    ]
    active, ignored = filter_components(components, ["internal-*"])
    assert len(active) == 2
    assert len(ignored) == 1
    assert ignored[0]["name"] == "internal-auth"
    assert ignored[0]["matched_pattern"] == "internal-*"


def test_filter_empty_patterns_keeps_all():
    components = [_comp("requests"), _comp("boto3")]
    active, ignored = filter_components(components, [])
    assert len(active) == 2
    assert len(ignored) == 0


def test_filter_all_ignored():
    components = [_comp("requests"), _comp("boto3")]
    active, ignored = filter_components(components, ["requests", "boto3"])
    assert len(active) == 0
    assert len(ignored) == 2


def test_filter_ignored_dict_has_expected_keys():
    components = [_comp("requests", purl="pkg:pypi/requests@2.31.0", version="2.31.0")]
    _, ignored = filter_components(components, ["requests"])
    entry = ignored[0]
    assert entry["name"] == "requests"
    assert entry["version"] == "2.31.0"
    assert entry["purl"] == "pkg:pypi/requests@2.31.0"
    assert entry["matched_pattern"] == "requests"


def test_filter_multiple_patterns_first_match_wins():
    comp = _comp("internal-db", purl="pkg:pypi/internal-db@0.1.0")
    active, ignored = filter_components([comp], ["internal-*", "pkg:pypi/internal-db@0.1.0"])
    assert len(ignored) == 1
    # matched by first applicable pattern
    assert ignored[0]["matched_pattern"] == "internal-*"
