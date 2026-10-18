from pathlib import Path
from pydantic_settings import BaseSettings, EnvSettingsSource, SettingsConfigDict

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
    path_timeout: float = 8.0
    path_rate_limit_ms: int = 250
    max_redirects: int = 5
    max_paths_per_domain_default: int = 40
    max_body_preview: int = 8192
    user_agent: str = "GeekNosy/1.0 (defensive security assessment)"
    data_dir: Path = Path("./data")

    model_config = SettingsConfigDict(env_prefix="GEEKNOSY_")

    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
    ):
        # Las variables nuevas tienen prioridad; conservar instalaciones anteriores.
        legacy_env = EnvSettingsSource(settings_cls, env_prefix="DATAGOBS_")
        return init_settings, env_settings, legacy_env, dotenv_settings, file_secret_settings


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
