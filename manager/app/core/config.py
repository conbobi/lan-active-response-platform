import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "LAN Active Response Platform Manager"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database configuration
    DATABASE_URL: str = "sqlite+aiosqlite:///./larp_manager.db"

    # Security & Execution
    SECRET_KEY: str = "larp-manager-secret-key-change-in-production"
    DEBUG: bool = True

    # Scheduler & Dead agent sweep thresholds (seconds)
    DEAD_AGENT_TIMEOUT_SECONDS: int = 30
    SWEEP_INTERVAL_SECONDS: int = 10

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
