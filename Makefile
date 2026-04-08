.PHONY: install test test-cov lint fmt fmt-check build clean

# ── Setup ────────────────────────────────────────────────────────────────────
install:
	pip install ".[dev]"

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	pytest

test-cov:
	pytest --cov=depscore --cov-report=term-missing --cov-report=xml

# ── Lint / Format ─────────────────────────────────────────────────────────────
lint:
	ruff check src/ tests/

fmt:
	ruff format src/ tests/

fmt-check:
	ruff format --check src/ tests/

# ── Build ────────────────────────────────────────────────────────────────────
build:
	python -m build

# ── Clean ────────────────────────────────────────────────────────────────────
clean:
	rm -rf dist/ build/ .coverage coverage.xml htmlcov/ .pytest_cache __pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
