from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from passlib.context import CryptContext
from database.db_config import config
from fastapi import HTTPException, status
import jwt
import secrets
import string
import asyncio
import hashlib
import hmac
from pathlib import Path

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def hash_password(password: str) -> str:
    # offload blocking bcrypt hash to thread
    hashed = await asyncio.to_thread(pwd_context.hash, password)
    return hashed

async def verify_password(plain: str, hashed: str) -> bool:
    result = await asyncio.to_thread(pwd_context.verify, plain, hashed)
    return result

def generate_email_verification_code(length: int = 6) -> str:
    """Generate a numeric verification code with a cryptographic RNG."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def hash_email_verification_code(user_id: UUID, code: str) -> str:
    """Return a domain-separated keyed digest; never persist the OTP itself."""
    secret = config.OTP_HMAC_SECRET.get_secret_value().encode("utf-8")
    message = f"email-verification\0{user_id}\0{code}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def _load_required_key(path: str, key_name: str) -> str:
    try:
        key_data = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        # Do not include key contents or environment-specific paths in startup errors.
        raise RuntimeError(f"Unable to load required {key_name}.") from None
    if not key_data.strip():
        raise RuntimeError(f"Required {key_name} is empty.")
    return key_data


def _load_and_validate_key_pair(private_path: str, public_path: str) -> tuple[str, str]:
    private_key_data = _load_required_key(private_path, "RSA private key")
    public_key_data = _load_required_key(public_path, "RSA public key")

    try:
        private_key = serialization.load_pem_private_key(
            private_key_data.encode("utf-8"),
            password=None,
        )
        public_key = serialization.load_pem_public_key(public_key_data.encode("utf-8"))
    except (TypeError, ValueError):
        raise RuntimeError("Unable to parse required RSA signing keys.") from None

    if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(
        public_key, rsa.RSAPublicKey
    ):
        raise RuntimeError("Configured signing keys must be RSA keys.")
    if private_key.key_size < 2048 or public_key.key_size < 2048:
        raise RuntimeError("Configured RSA signing keys are too small.")
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise RuntimeError("Configured RSA signing keys do not match.")

    return private_key_data, public_key_data


PRIVATE_KEY, PUBLIC_KEY = _load_and_validate_key_pair(
    config.PRIVATE_KEY_PATH,
    config.PUBLIC_KEY_PATH,
)


def _create_token(
    subject: str,
    token_type: Literal["access", "refresh"],
    expires_delta: timedelta,
    audience: str,
    extra_claims: dict[str, Any] | None,
) -> str:
    now = datetime.now(timezone.utc)
    to_encode = dict(extra_claims or {})
    to_encode.update(
        {
            "sub": str(UUID(subject)),
            "iss": config.JWT_ISSUER,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + expires_delta,
            "type": token_type,
        }
    )
    return jwt.encode(
        to_encode,
        PRIVATE_KEY,
        algorithm=config.ALGORITHM,
        headers={"kid": config.JWT_KEY_ID},
    )

def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    return _create_token(
        subject=subject,
        token_type="access",
        expires_delta=timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        audience=config.JWT_ACCESS_AUDIENCE,
        extra_claims=extra_claims,
    )

def create_refresh_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    return _create_token(
        subject=subject,
        token_type="refresh",
        expires_delta=timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS),
        audience=config.JWT_REFRESH_AUDIENCE,
        extra_claims=extra_claims,
    )


def decode_token(
    token: str,
    expected_type: Literal["access", "refresh"],
) -> dict[str, Any]:
    audience = (
        config.JWT_ACCESS_AUDIENCE
        if expected_type == "access"
        else config.JWT_REFRESH_AUDIENCE
    )
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != config.ALGORITHM or header.get("kid") != config.JWT_KEY_ID:
            raise jwt.InvalidTokenError
        payload: dict[str, Any] = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[config.ALGORITHM],
            issuer=config.JWT_ISSUER,
            audience=audience,
            options={"require": ["exp", "sub", "iss", "aud", "nbf", "type"]},
        )
        if payload.get("type") != expected_type:
            raise jwt.InvalidTokenError
        UUID(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except (jwt.InvalidTokenError, TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload
