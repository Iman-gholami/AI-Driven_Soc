from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Real-Time SOC Incident Analysis API"
    environment: str = "production"
    log_level: str = "INFO"
    openai_api_key: str
    openai_model: str = "gpt-4.1"
    openai_timeout_seconds: float = 5.0
    max_raw_log_chars: int = 4000
    max_payload_size_bytes: int = 200_000
    enable_rate_limiting: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
