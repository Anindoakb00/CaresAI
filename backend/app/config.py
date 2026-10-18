from functools import lru_cache
import os

from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "CareShield AI"
    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./careshield.db"))
    session_ttl_hours: int = Field(default_factory=lambda: int(os.getenv("SESSION_TTL_HOURS", "8")))
    secret_key: str = Field(default_factory=lambda: os.getenv("SECRET_KEY", "local-demo-secret-change-me"))
    frontend_origin: str = Field(default_factory=lambda: os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"))
    seed_demo_data: bool = Field(default_factory=lambda: os.getenv("SEED_DEMO_DATA", "true").lower() == "true")
    model_version: str = "isolation-forest-v1"


@lru_cache
def get_settings() -> Settings:
    return Settings()

