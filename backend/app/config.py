from pathlib import Path
from typing import Annotated

from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from pydantic import field_validator

# Puntos por header (modo estándar)
HEADER_POINTS = {
    "content-security-policy": 15,
    "strict-transport-security": 15,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 5,
    "permissions-policy": 5,
    "x-xss-protection": 3,
}

ADVANCED_HEADER_POINTS = {
    **HEADER_POINTS,
    "cross-origin-opener-policy": 5,
    "cross-origin-embedder-policy": 5,
    "cross-origin-resource-policy": 5,
}

SECURITY_HEADERS = list(HEADER_POINTS.keys())
ADVANCED_SECURITY_HEADERS = list(ADVANCED_HEADER_POINTS.keys())

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DATAGOBS_")
    database_url: str = "sqlite+aiosqlite:///./data/datagobs.db"
    scan_timeout: float = 15.0
    path_timeout: float = 8.0
    path_rate_limit_ms: int = 250
    max_redirects: int = 5
    max_paths_per_domain_default: int = 40
    max_body_preview: int = 8192
    user_agent: str = "DataGobs/1.0 (defensive security assessment; +https://github.com/datagobs)"
    data_dir: Path = Path("./data")
    api_keys: Annotated[list[str], NoDecode] = []
    cors_origins: Annotated[list[str], NoDecode] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    require_authorization_confirmation: bool = True
    allow_private_targets: bool = False
    allowed_domains: Annotated[list[str], NoDecode] = []
    allowed_cidrs: Annotated[list[str], NoDecode] = []
    allowed_ports: Annotated[list[int], NoDecode] = [80, 443]
    global_requests_per_second: float = 20.0
    per_host_requests_per_second: float = 4.0
    max_concurrent_requests: int = 20
    max_concurrent_per_host: int = 3
    max_domains_per_job: int = 100
    max_response_bytes: int = 2_000_000
    worker_poll_seconds: float = 1.0
    worker_id: str = "local-worker"
    inline_worker: bool = True
    webhook_url: str | None = None
    webhook_secret: str | None = None
    template_signing_secret: str | None = None
    log_level: str = "INFO"

    @field_validator(
        "api_keys",
        "cors_origins",
        "allowed_domains",
        "allowed_cidrs",
        mode="before",
    )
    @classmethod
    def split_csv(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("allowed_ports", mode="before")
    @classmethod
    def split_ports(cls, value):
        if isinstance(value, str):
            return [int(item.strip()) for item in value.split(",") if item.strip()]
        return value

settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
