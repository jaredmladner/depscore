<p align="center">
  <img src="src/depscore/assets/icon.svg" width="96" height="96" alt="depscore icon"/>
</p>

<h1 align="center">depscore</h1>

<p align="center">
  <strong>AI-powered SBOM dependency scoring</strong><br/>
  <sub>Maturity · Maintainability · Security Posture · Community Health</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-6366f1?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-Apache%202.0-22c55e?style=flat-square"/>
  <img src="https://img.shields.io/badge/SBOM-CycloneDX%20%7C%20SPDX-3b82f6?style=flat-square"/>
  <img src="https://img.shields.io/badge/AI-Claude%20Sonnet-818cf8?style=flat-square&logo=anthropic&logoColor=white"/>
</p>

---

**AI-powered SBOM dependency scoring.** `depscore` reads a standard SBOM file (CycloneDX or SPDX JSON), enriches every dependency with real-time data from GitHub, OSV, OpenSSF Scorecard, and package registries, then uses a hybrid rules + Claude AI engine to score each one across four risk dimensions — producing a JSON report and optional HTML dashboard.

---

## Why depscore?

An SBOM tells you *what* is in your software. `depscore` tells you *how risky* each of those dependencies is. A library that hasn't been touched in 3 years, has unvetted foreign contributors, and carries unpatched CVEs is a very different risk profile than a well-maintained, actively reviewed project — even if both appear identically in an SBOM.

---

## Scoring Dimensions

Each dependency is scored 0–100 across four dimensions:

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| **Security Posture** | 35% | CVE history & severity, SECURITY.md, branch protection, signed commits, OpenSSF Scorecard |
| **Maintainability** | 30% | Commit recency & frequency, PR response time, bus factor (contributor concentration) |
| **Maturity** | 20% | Version stability, project age, release cadence, download adoption |
| **Community Health** | 15% | Contributor diversity, geographic/corporate concentration, SourceRank |

The **overall score** is a weighted average of the four dimensions. A letter grade (A–F) is assigned:

| Grade | Score |
|-------|-------|
| A | 80 – 100 |
| B | 65 – 79 |
| C | 50 – 64 |
| D | 35 – 49 |
| F | 0 – 34 |

### Hybrid Scoring

`depscore` blends two layers:

- **Rules layer (40%)** — deterministic math on raw metrics (e.g., days since last commit, CVE count, version prefix)
- **AI layer (60%)** — Claude `claude-sonnet-4-6` receives all enriched signals and synthesizes a nuanced score with written reasoning per dimension

If the AI layer is unavailable or disabled, scoring falls back to rules-only automatically.

### API Cost Estimate

`depscore` uses the [Anthropic API](https://console.anthropic.com) (separate from a claude.ai subscription — see below) for AI scoring. Costs are per-token and very low:

| SBOM size | Estimated cost |
|-----------|---------------|
| 10 dependencies | ~$0.03 – $0.05 |
| 50 dependencies | ~$0.15 – $0.25 |
| 100 dependencies | ~$0.30 – $0.50 |
| 500 dependencies | ~$1.50 – $2.50 |

> Estimates based on `claude-sonnet-4-6` pricing at ~$3/M input tokens and ~$15/M output tokens, with ~800–1,500 tokens input and ~300 tokens output per dependency.

**No Anthropic API key?** Use `--no-ai` for free rules-based scoring with no external AI calls.

> **Note:** A [claude.ai](https://claude.ai) subscription (Pro/Team/Max) is a separate product from the Anthropic API and does **not** include API access. API credits are purchased independently at [console.anthropic.com](https://console.anthropic.com) (minimum $5).
>
> **Important:** Add credits to your account *before* generating your API key. API keys created on a zero-balance account will continue to return a billing error even after credits are added later — generate a fresh key after funding your account.

---

## Data Sources

| Source | Data collected |
|--------|---------------|
| **GitHub API** | Commits, contributors, bus factor, branch protection, SECURITY.md, PR age |
| **OpenSSF Scorecard** | Aggregate security score, per-check breakdown |
| **OSV (Open Source Vulnerabilities)** | CVE history, severity counts |
| **Libraries.io** | Dependents, SourceRank, release history |
| **PyPI** | Python package metadata & download stats |
| **npm** | JavaScript package metadata |
| **Maven Central** | Java/JVM package metadata |
| **NuGet** | .NET package metadata |

---

## Installation

**Requirements:** Python 3.11+

```bash
# From source
git clone https://github.com/your-org/depscore.git
cd depscore
pip install .

# With dev dependencies
pip install ".[dev]"
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

```bash
# Required
GITHUB_TOKEN=ghp_...           # GitHub personal access token (read-only scopes are fine)
ANTHROPIC_API_KEY=sk-ant-...   # Anthropic API key

# Optional
LIBRARIES_IO_API_KEY=          # Improves enrichment quality (free tier available)

# Tuning (defaults shown)
DEPSCORE_AI_ENABLED=true
DEPSCORE_AI_BLEND_WEIGHT=0.6   # 0.0 = rules only, 1.0 = AI only
DEPSCORE_CONCURRENCY_LIMIT=10  # Parallel dependency enrichments
DEPSCORE_REQUEST_TIMEOUT_SECONDS=30
DEPSCORE_MAX_RETRIES=3
```

---

## Usage

### Basic scan (JSON output)
```bash
depscore scan --sbom ./sbom.json
```

### With HTML dashboard
```bash
depscore scan --sbom ./sbom.json --html
```

### Specify SBOM format explicitly
```bash
depscore scan --sbom ./sbom.json --format cyclonedx --output ./reports --html
depscore scan --sbom ./sbom.spdx.json --format spdx --output ./reports --html
```

> Format is **auto-detected** by default — `--format` is only needed if auto-detection fails.

### Rules-only mode (no AI, faster, no Anthropic key needed)
```bash
depscore scan --sbom ./sbom.json --no-ai
```

### All options
```
Options:
  --sbom PATH                 Path to the SBOM file  [required]
  --format [cyclonedx|spdx|auto]
                              SBOM format  [default: auto]
  --output PATH               Output directory  [default: ./depscore-output]
  --html                      Also generate an HTML dashboard
  --no-ai                     Skip AI scoring (rules-based only)
  --version                   Show version and exit
  --help                      Show this message and exit
```

---

## Output

### JSON report (`depscore-report.json`)

```json
{
  "overall_sbom_score": 74.3,
  "overall_sbom_grade": "C",
  "total_dependencies": 42,
  "grade_distribution": { "A": 8, "B": 12, "C": 14, "D": 6, "F": 2 },
  "dimension_averages": {
    "maturity": 81.2,
    "maintainability": 70.5,
    "security_posture": 65.1,
    "community_health": 77.8
  },
  "scores": [
    {
      "dependency_name": "requests",
      "version": "2.31.0",
      "overall": 88.4,
      "overall_grade": "A",
      "maturity": { "score": 91, "confidence": 0.95, "reasoning": "..." },
      "maintainability": { "score": 82, "confidence": 0.90, "reasoning": "..." },
      "security_posture": { "score": 74, "confidence": 0.85, "reasoning": "..." },
      "community_health": { "score": 85, "confidence": 0.88, "reasoning": "..." },
      "ai_reasoning": "Full Claude reasoning block...",
      "scored_at": "2026-03-25T14:00:00Z"
    }
  ]
}
```

### HTML Dashboard

A self-contained `.html` file (no server required) including:
- Overall SBOM score gauge
- Grade distribution chart
- Per-dimension radar chart
- Sortable, filterable dependency table
- Per-dependency drill-down with CVE list, Scorecard checks, and AI reasoning

---

## Docker

```bash
# Build
docker build -t depscore .

# Scan with JSON output
docker run --rm \
  -e GITHUB_TOKEN=ghp_... \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -v /path/to/sbom.json:/sbom/sbom.json:ro \
  -v $(pwd)/report:/output \
  depscore scan --sbom /sbom/sbom.json --output /output

docker run --rm \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v ./result.json:/sbom/sbom.json:ro \
  -v $(pwd)/report:/output \
  depscore scan --sbom /sbom/sbom.json --output /output

# Scan with HTML dashboard, rules-only (no Anthropic key needed)
docker run --rm \
  -e GITHUB_TOKEN=ghp_... \
  -v /path/to/sbom.json:/sbom/sbom.json:ro \
  -v $(pwd)/report:/output \
  depscore scan --sbom /sbom/sbom.json --output /output --html --no-ai
```

Mount your SBOM at `/sbom/` (read-only) and collect output from `/output/`.

---

## Generating an SBOM

`depscore` consumes SBOMs — it does not generate them. Use [Syft](https://github.com/anchore/syft) to generate one from your project or container:

```bash
# Install Syft
brew install anchore/syft/syft   # macOS
# or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Scan a directory → CycloneDX JSON
syft dir:. -o cyclonedx-json > sbom.json

# Scan a container image → SPDX JSON
syft ubuntu:latest -o spdx-json > sbom.spdx.json

# Then score it
depscore scan --sbom sbom.json --html
```

---

## Development

```bash
# Install with dev dependencies
pip install ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=depscore --cov-report=term-missing
```

### Project structure

```
src/depscore/
├── cli.py              # Click CLI entry point
├── config.py           # Environment-based configuration
├── exceptions.py       # Custom exception hierarchy
├── models/             # Pydantic data models (SBOM, enrichment, scores)
├── parsers/            # CycloneDX and SPDX JSON parsers
├── enrichment/         # Async data enrichers (GitHub, OSV, registries, etc.)
├── scoring/            # Rules engine, Claude AI scorer, blender
├── output/             # JSON and HTML report writers
└── templates/          # Jinja2 HTML dashboard template
```

---

## License

Apache 2.0 — free to use, modify, repackage, and sell. See [LICENSE](LICENSE).
