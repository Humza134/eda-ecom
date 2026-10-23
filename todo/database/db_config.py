from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    JWKS_URL: str
    JWT_ISSUER: str
    JWT_AUDIENCE: str
    ALGORITHM: Literal["RS256"] = "RS256"
    # (optionally) pool_size: int = 10
    # (optionally) max_overflow: int = 20
    # add other DB-related configs as needed

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


config = Settings()
