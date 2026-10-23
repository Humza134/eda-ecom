from ipaddress import ip_network
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int
    PRIVATE_KEY_PATH: str
    PUBLIC_KEY_PATH: str
    ALGORITHM: Literal["RS256"] = "RS256"
    JWT_KEY_ID: str
    JWT_ISSUER: str
    JWT_ACCESS_AUDIENCE: str
    JWT_REFRESH_AUDIENCE: str
    EMAIL_USER: str
    EMAIL_PASS: str
    SMTP_HOST: str
    SMTP_PORT: int
    OTP_HMAC_SECRET: SecretStr = Field(min_length=32)
    OTP_EXPIRY_SECONDS: int = Field(default=600, gt=0)
    OTP_MAX_ATTEMPTS: int = Field(default=5, gt=0, le=20)
    RATE_LIMIT_KEY_SECRET: SecretStr = Field(min_length=32)
    REDIS_URL: SecretStr = SecretStr("redis://redis:6379/0")
    REDIS_CONNECT_TIMEOUT_SECONDS: float = Field(default=2.0, gt=0)
    REDIS_SOCKET_TIMEOUT_SECONDS: float = Field(default=2.0, gt=0)
    REDIS_RATE_LIMIT_KEY_PREFIX: str = Field(
        default="auth-rate-limit",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9:_-]+$",
    )
    TRUSTED_PROXY_CIDRS: str = ""
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=300, gt=0)
    LOGIN_ACCOUNT_RATE_LIMIT: int = Field(default=5, gt=0)
    LOGIN_CLIENT_RATE_LIMIT: int = Field(default=20, gt=0)
    SIGNUP_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=3600, gt=0)
    SIGNUP_ACCOUNT_RATE_LIMIT: int = Field(default=3, gt=0)
    SIGNUP_CLIENT_RATE_LIMIT: int = Field(default=10, gt=0)
    VERIFY_EMAIL_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=900, gt=0)
    VERIFY_EMAIL_ACCOUNT_RATE_LIMIT: int = Field(default=5, gt=0)
    VERIFY_EMAIL_CLIENT_RATE_LIMIT: int = Field(default=30, gt=0)
    RESEND_OTP_COOLDOWN_SECONDS: int = Field(default=60, gt=0)
    RESEND_OTP_ACCOUNT_RATE_LIMIT: int = Field(default=1, gt=0)
    RESEND_OTP_CLIENT_RATE_LIMIT: int = Field(default=10, gt=0)
    REFRESH_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, gt=0)
    REFRESH_TOKEN_RATE_LIMIT: int = Field(default=30, gt=0)
    REFRESH_CLIENT_RATE_LIMIT: int = Field(default=120, gt=0)
    # (optionally) pool_size: int = 10
    # (optionally) max_overflow: int = 20
    # add other DB-related configs as needed

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("TRUSTED_PROXY_CIDRS")
    @classmethod
    def validate_trusted_proxy_cidrs(cls, value: str) -> str:
        for item in value.split(","):
            if item.strip():
                ip_network(item.strip(), strict=False)
        return value


config = Settings()
