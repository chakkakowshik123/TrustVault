"""Application configuration loaded from environment / .env file."""
import secrets
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App metadata
    APP_NAME: str = "TrustVault"
    APP_VERSION: str = "1.0.0"

    # Security — override in production via environment variable
    SECRET_KEY: str = secrets.token_hex(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database
    DATABASE_URL: str = "sqlite:///./trustvault.db"

    # File storage — private directory, never served directly
    UPLOAD_DIR: Path = Path("uploads")
    MAX_FILE_SIZE_MB: int = 50

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()

# Ensure upload directory exists at import time
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
