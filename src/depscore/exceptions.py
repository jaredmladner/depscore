class DepscoreError(Exception):
    """Base exception for depscore."""


class ConfigurationError(DepscoreError):
    """Missing or invalid configuration."""


class SBOMParseError(DepscoreError):
    """SBOM file unreadable or invalid schema."""


class EnrichmentError(DepscoreError):
    """Base enrichment error."""


class RateLimitError(EnrichmentError):
    """HTTP 429 received from upstream API."""

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class NotFoundError(EnrichmentError):
    """Package or repo not found in upstream source."""


class AuthenticationError(EnrichmentError):
    """Bad or missing API token (401/403)."""


class NetworkError(EnrichmentError):
    """Timeout or connection failure."""


class ScoringError(DepscoreError):
    """Error during rules math or AI response parsing."""


class OutputError(DepscoreError):
    """File write failure."""
