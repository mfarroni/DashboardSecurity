from pydantic import BaseSettings, Field
from typing import Optional
import os
from pathlib import Path


# Detect if running in Docker
IN_DOCKER = os.path.exists("/.dockerenv")
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # Database
    database_url: str = Field(
        default="sqlite:///data/security.db" if not IN_DOCKER else "sqlite:///data/security.db", 
        alias="DATABASE_URL"
    )
    
    # NVD API
    nvd_api_key: Optional[str] = Field(default=None, alias="NVD_API_KEY")
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_rate_limit_per_30s: int = Field(default=5, alias="NVD_RATE_LIMIT")  # 5 without key, 50 with key
    
    # Application
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    secret_key: str = Field(default="dev-secret-change-in-production", alias="SECRET_KEY")
    timezone: str = Field(default="Europe/Rome", alias="TZ")
    
    # Paths - use local paths for dev, /app for Docker
    data_dir: str = str(BASE_DIR / "data") if not IN_DOCKER else "/app/data"
    logs_dir: str = str(BASE_DIR / "logs") if not IN_DOCKER else "/app/logs"
    config_dir: str = str(BASE_DIR / "config") if not IN_DOCKER else "/app/config"
    
    # FeedHub
    feedhub_import_dir: str = str(BASE_DIR / "data" / "feedhub_imports") if not IN_DOCKER else "/app/data/feedhub_imports"
    
    # Perimetro
    perimetro_import_dir: str = str(BASE_DIR / "data" / "perimetro_imports") if not IN_DOCKER else "/app/data/perimetro_imports"
    
    # Syslog
    syslog_import_dir: str = str(BASE_DIR / "data" / "syslog_imports") if not IN_DOCKER else "/app/data/syslog_imports"
    
    # Scheduler
    nvd_sync_interval_hours: int = 6
    feed_sync_interval_hours: int = 1
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()

# Ensure directories exist
for dir_path in [
    settings.data_dir,
    settings.logs_dir,
    settings.config_dir,
    settings.feedhub_import_dir,
    settings.perimetro_import_dir,
    settings.syslog_import_dir,
]:
    os.makedirs(dir_path, exist_ok=True)