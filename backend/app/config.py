from pathlib import Path
from pydantic_settings import BaseSettings

DEFAULT_PATHS = [
    "/",
    "/web/",
    "/administrator/",
    "/web/administrator/",
    "/component/users",
    "/web/component/users",
    "/web/index.php/component/users",
]

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
    database_url: str = "sqlite+aiosqlite:///./data/datagobs.db"
    scan_timeout: float = 15.0
    max_redirects: int = 10
    user_agent: str = "DataGobs/1.0 (defensive security assessment; +https://github.com/datagobs)"
    data_dir: Path = Path("./data")

    class Config:
        env_prefix = "DATAGOBS_"


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
