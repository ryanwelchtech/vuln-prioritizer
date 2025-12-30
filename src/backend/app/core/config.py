"""
Application configuration settings.
"""
from typing import List
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings."""

    # Application
    APP_NAME: str = "Vulnerability Prioritization Engine"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production-use-strong-secret"

    # Database (SQLite for dev, PostgreSQL for production)
    DATABASE_URL: str = "sqlite+aiosqlite:///./vuln.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001"]

    # JWT
    JWT_SECRET_KEY: str = "jwt-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60

    # External APIs
    NVD_API_KEY: str = ""
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    KEV_FEED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Integrations
    JIRA_URL: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_PROJECT_KEY: str = "VULN"
    SLACK_WEBHOOK_URL: str = ""

    # Scanning
    SCAN_CACHE_TTL: int = 3600  # 1 hour
    CVE_CACHE_TTL: int = 86400  # 24 hours

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
