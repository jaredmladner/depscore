from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Required
    github_token: str
    anthropic_api_key: str

    # Optional
    libraries_io_api_key: str | None = None

    # Tuning — set via DEPSCORE_* env vars
    depscore_ai_enabled: bool = True
    depscore_ai_blend_weight: float = 0.6
    depscore_concurrency_limit: int = 10
    depscore_request_timeout_seconds: float = 30.0
    depscore_max_retries: int = 3

    @property
    def ai_enabled(self) -> bool:
        return self.depscore_ai_enabled

    @property
    def ai_blend_weight(self) -> float:
        return self.depscore_ai_blend_weight

    @property
    def concurrency_limit(self) -> int:
        return self.depscore_concurrency_limit

    @property
    def request_timeout_seconds(self) -> float:
        return self.depscore_request_timeout_seconds

    @property
    def max_retries(self) -> int:
        return self.depscore_max_retries

    @classmethod
    def load(cls) -> "Settings":
        try:
            return cls(
                _env_file=".env",
            )
        except Exception as exc:
            from depscore.exceptions import ConfigurationError
            raise ConfigurationError(
                f"Configuration error: {exc}\n"
                "Ensure GITHUB_TOKEN and ANTHROPIC_API_KEY are set."
            ) from exc


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings
