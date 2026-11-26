from typing import Annotated, Literal
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


TokenDigest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class NetworkOperator(BaseModel):
    token_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role: Literal["analyst", "operator", "admin"]
    agents: set[str]

    @model_validator(mode="after")
    def require_operator_scope(self):
        if self.role == "operator" and not self.agents:
            raise ValueError("Response operators require explicit Agent scope")
        return self


class NetworkSSHProbe(BaseModel):
    host: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$")
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    port: int = Field(ge=1, le=65535)


class LabWaf(BaseModel):
    directory: str
    disposable_peers: set[str]
    protected_peers: set[str]


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
    OPERATOR_SESSION_KEY: str | None = Field(default=None, min_length=32, repr=False)
    JWT_SECRET_KEY: str | None = Field(default=None, min_length=32, repr=False)
    JWT_KEY_ID: str = Field(default="v1", min_length=1, max_length=32)
    JWT_PREVIOUS_KEYS: dict[str, str] = Field(default_factory=dict, repr=False)
    JWT_ISSUER: str = "larp-manager"
    JWT_AUDIENCE: str = "larp-soc-dashboard"
    JWT_ACCESS_TTL_SECONDS: int = Field(default=900, ge=60, le=3600)
    REFRESH_TOKEN_TTL_SECONDS: int = Field(default=7 * 24 * 3600, ge=300, le=90 * 24 * 3600)
    REFRESH_COOKIE_NAME: str = "larp_refresh_token"
    REFRESH_COOKIE_SECURE: bool | None = None
    REFRESH_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    REFRESH_COOKIE_DOMAIN: str | None = None
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost",
            "https://edr.alwayready.id.vn",
        ]
    )
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, ge=10, le=3600)
    AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = Field(default=10, ge=1, le=200)
    AUTH_LOCKOUT_THRESHOLD: int = Field(default=5, ge=1, le=50)
    AUTH_LOCKOUT_SECONDS: int = Field(default=300, ge=30, le=86400)
    ALLOW_LEGACY_OPERATOR_TOKENS: bool = True
    NETWORK_OPERATORS: dict[Annotated[str, Field(min_length=1, max_length=64)], NetworkOperator] = Field(default_factory=dict, repr=False)
    HTTP_RESPONSE_LAB_WAFS: dict[str, LabWaf] = Field(default_factory=dict)
    NETWORK_SSH_PROBES: dict[str, NetworkSSHProbe] = Field(default_factory=dict, repr=False)
    NETWORK_LEGACY_ADMIN_TOKEN: TokenDigest | None = Field(default=None, repr=False)

    # Scheduler & Dead agent sweep thresholds (seconds)
    DEAD_AGENT_TIMEOUT_SECONDS: int = 30
    SWEEP_INTERVAL_SECONDS: int = 10

    @model_validator(mode="after")
    def distinct_network_tokens(self):
        from pathlib import Path
        waf_dirs = [Path(item.directory).resolve() for item in self.HTTP_RESPONSE_LAB_WAFS.values()]
        if len(set(waf_dirs)) != len(waf_dirs):
            raise ValueError("Each lab Agent requires its own application enforcement directory")
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
