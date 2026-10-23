from uuid import UUID

from fastapi import Header, HTTPException, status
from jwt import PyJWKClient, decode, get_unverified_header
from jwt.exceptions import (
    InvalidTokenError,
    PyJWKClientConnectionError,
    PyJWKClientError,
)

from database.db_config import config

jwk_client = PyJWKClient(config.JWKS_URL)


def get_current_user_id(authorization: str | None = Header(default=None)) -> UUID:
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid auth header",
        )
    scheme, _, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth header")

    try:
        header = get_unverified_header(token)
        if header.get("alg") != config.ALGORITHM or not header.get("kid"):
            raise InvalidTokenError
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        payload = decode(
            token,
            signing_key,
            algorithms=[config.ALGORITHM],
            issuer=config.JWT_ISSUER,
            audience=config.JWT_AUDIENCE,
            options={"require": ["exp", "sub", "iss", "aud", "nbf", "type"]},
        )
        if payload.get("type") != "access":
            raise InvalidTokenError
        return UUID(payload["sub"])
    except PyJWKClientConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable",
        ) from None
    except (InvalidTokenError, PyJWKClientError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from None
