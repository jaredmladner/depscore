from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def cyclonedx_path() -> Path:
    return FIXTURES_DIR / "sample.cyclonedx.json"


@pytest.fixture
def spdx_path() -> Path:
    return FIXTURES_DIR / "sample.spdx.json"
