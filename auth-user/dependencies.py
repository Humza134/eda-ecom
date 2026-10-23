from typing import Annotated
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from model.user_model import (
    EmailVerificationRequest,
    EmailVerificationResendRequest,
    User,
    UserCreate,
)
from database.connection import get_session
from database.db_config import config
from rate_limit import (
    RedisRateLimitStore,
    RateLimitRule,
    enforce_rate_limits,
    get_client_identifier,
)
from utils import decode_token
from uuid import UUID

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _enforce_auth_rate_limit(
    *,
    request: Request,
    endpoint: str,
    subject_identifiers: tuple[str, ...],
    client_requests: int,
    subject_requests: int,
    window_seconds: int,
) -> None:
    redis_client: Redis = request.app.state.redis
    await enforce_rate_limits(
        store=RedisRateLimitStore(redis_client),
        endpoint=endpoint,
        client_identifier=get_client_identifier(request),
        subject_identifiers=subject_identifiers,
        client_rule=RateLimitRule(client_requests, window_seconds),
        subject_rule=RateLimitRule(subject_requests, window_seconds),
    )


async def rate_limit_signup(
    request: Request,
    user_in: UserCreate,
) -> None:
    await _enforce_auth_rate_limit(
        request=request,
        endpoint="signup",
        subject_identifiers=(
            f"username:{user_in.username.strip().casefold()}",
            f"email:{str(user_in.email).strip().casefold()}",
        ),
        client_requests=config.SIGNUP_CLIENT_RATE_LIMIT,
        subject_requests=config.SIGNUP_ACCOUNT_RATE_LIMIT,
        window_seconds=config.SIGNUP_RATE_LIMIT_WINDOW_SECONDS,
    )


async def rate_limit_login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> None:
    await _enforce_auth_rate_limit(
        request=request,
        endpoint="login",
        subject_identifiers=(form_data.username.strip().casefold(),),
        client_requests=config.LOGIN_CLIENT_RATE_LIMIT,
        subject_requests=config.LOGIN_ACCOUNT_RATE_LIMIT,
        window_seconds=config.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    )


async def rate_limit_verify_email(
    request: Request,
    verification: EmailVerificationRequest,
) -> None:
    await _enforce_auth_rate_limit(
        request=request,
        endpoint="verify-email",
        subject_identifiers=(str(verification.user_id),),
        client_requests=config.VERIFY_EMAIL_CLIENT_RATE_LIMIT,
        subject_requests=config.VERIFY_EMAIL_ACCOUNT_RATE_LIMIT,
        window_seconds=config.VERIFY_EMAIL_RATE_LIMIT_WINDOW_SECONDS,
    )


async def rate_limit_resend_verification(
    request: Request,
    resend: EmailVerificationResendRequest,
) -> None:
    await _enforce_auth_rate_limit(
        request=request,
        endpoint="resend-verification",
        subject_identifiers=(str(resend.email).strip().casefold(),),
        client_requests=config.RESEND_OTP_CLIENT_RATE_LIMIT,
        subject_requests=config.RESEND_OTP_ACCOUNT_RATE_LIMIT,
        window_seconds=config.RESEND_OTP_COOLDOWN_SECONDS,
    )


async def rate_limit_refresh(
    request: Request,
    token: Annotated[str, Depends(oauth2_scheme)],
) -> None:
    await _enforce_auth_rate_limit(
        request=request,
        endpoint="refresh",
        subject_identifiers=(token,),
        client_requests=config.REFRESH_CLIENT_RATE_LIMIT,
        subject_requests=config.REFRESH_TOKEN_RATE_LIMIT,
        window_seconds=config.REFRESH_RATE_LIMIT_WINDOW_SECONDS,
    )

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_session)]
)-> User:
    try:
        payload = decode_token(token, expected_type="access")
        user_id_str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        # Convert to UUID (since your User.uid is UUID)
        user_id: UUID = UUID(user_id_str)
    except Exception as e:
        # optionally log e
        # If decode_token already raised, just re-raise credentials_exception
        raise credentials_exception

    # fetch user from DB
    result = await db.exec(select(User).where(User.uid == user_id))
    user = result.first()
    if user is None:
        raise credentials_exception

    return user

async def validate_refresh_token(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_session),
) -> User:
    """
    This dependency validates the incoming token is of type 'refresh'
    and returns the user for whom the token was issued.
    """
    try:
        payload = decode_token(token, expected_type="refresh")
        user_id_str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = UUID(user_id_str)
    except Exception:
        raise credentials_exception

    result = await db.exec(select(User).where(User.uid == user_id))
    user = result.first()
    if not user:
        raise credentials_exception
    # optionally check if refresh token is still valid in DB (revoked checks etc)
    return user
