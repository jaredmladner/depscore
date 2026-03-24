from pathlib import Path

import pytest

from depscore.parsers.cyclonedx import CycloneDXParser
from depscore.parsers.spdx import SPDXParser


def test_cyclonedx_parse(cyclonedx_path: Path) -> None:
    parsed = CycloneDXParser().parse(cyclonedx_path)
    assert parsed.format == "cyclonedx"
    assert parsed.spec_version == "1.5"
    assert len(parsed.components) == 5

    requests = next(c for c in parsed.components if c.name == "requests")
    assert requests.version == "2.31.0"
    assert requests.ecosystem == "pypi"
    assert requests.purl == "pkg:pypi/requests@2.31.0"
    assert requests.repository_url is not None
    assert "github.com" in requests.repository_url
    assert requests.license == "Apache-2.0"


def test_cyclonedx_npm_component(cyclonedx_path: Path) -> None:
    parsed = CycloneDXParser().parse(cyclonedx_path)
    lodash = next(c for c in parsed.components if c.name == "lodash")
    assert lodash.ecosystem == "npm"


def test_cyclonedx_maven_component(cyclonedx_path: Path) -> None:
    parsed = CycloneDXParser().parse(cyclonedx_path)
    spring = next(c for c in parsed.components if "spring-core" in c.name)
    assert spring.ecosystem == "maven"


def test_spdx_parse(spdx_path: Path) -> None:
    parsed = SPDXParser().parse(spdx_path)
    assert parsed.format == "spdx"
    assert parsed.spec_version == "SPDX-2.3"
    assert len(parsed.components) == 5

    flask = next(c for c in parsed.components if c.name == "flask")
    assert flask.version == "3.0.0"
    assert flask.ecosystem == "pypi"
    assert flask.license == "BSD-3-Clause"


def test_spdx_purl_extraction(spdx_path: Path) -> None:
    parsed = SPDXParser().parse(spdx_path)
    nuget = next(c for c in parsed.components if c.name == "Newtonsoft.Json")
    assert nuget.ecosystem == "nuget"
    assert nuget.purl is not None


def test_cyclonedx_invalid_file(tmp_path: Path) -> None:
    from depscore.exceptions import SBOMParseError
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "cyclonedx"}')
    with pytest.raises(SBOMParseError):
        CycloneDXParser().parse(bad)
