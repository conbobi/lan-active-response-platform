from typing import Annotated, Literal
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


TokenDigest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class NetworkOperator(BaseModel):
    token_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role: Literal["analyst", "admin"]
    agents: set[str]


class NetworkSSHProbe(BaseModel):
    host: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$")
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    port: int = Field(ge=1, le=65535)


class Settings(BaseSettings):
    PROJECT_NAME: str = "LAN Active Response Platform Manager"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database configuration
    DATABASE_URL: str = "sqlite+aiosqlite:///./larp_manager.db"

    # Security & Execution
    SECRET_KEY: str = "larp-manager-secret-key-change-in-production"
    DEBUG: bool = True
    NETWORK_AGENT_TOKENS: dict[str, TokenDigest] = Field(default_factory=dict, repr=False)
    NETWORK_OPERATORS: dict[Annotated[str, Field(min_length=1, max_length=64)], NetworkOperator] = Field(default_factory=dict, repr=False)
    NETWORK_SSH_PROBES: dict[str, NetworkSSHProbe] = Field(default_factory=dict, repr=False)
    NETWORK_LEGACY_ADMIN_TOKEN: TokenDigest | None = Field(default=None, repr=False)

    # Scheduler & Dead agent sweep thresholds (seconds)
    DEAD_AGENT_TIMEOUT_SECONDS: int = 30
    SWEEP_INTERVAL_SECONDS: int = 10

    @model_validator(mode="after")
    def distinct_network_tokens(self):
        digests = [*self.NETWORK_AGENT_TOKENS.values(),
                   *(operator.token_sha256 for operator in self.NETWORK_OPERATORS.values())]
        if self.NETWORK_LEGACY_ADMIN_TOKEN:
            digests.append(self.NETWORK_LEGACY_ADMIN_TOKEN)
        if len(set(digests)) != len(digests):
            raise ValueError("Use distinct credentials for each network Agent and operator")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
