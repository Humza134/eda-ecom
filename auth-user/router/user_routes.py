import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession

from database.connection import get_session
from dependencies import (
    get_current_user,
    rate_limit_login,
    rate_limit_refresh,
    rate_limit_resend_verification,
    rate_limit_signup,
    rate_limit_verify_email,
    validate_refresh_token,
)
from model.user_model import (
    EmailVerificationRequest,
    EmailVerificationResendRequest,
    Token,
    User,
    UserCreate,
    UserRead,
    UserUpdate,
)
from service.user_service import (
    EmailNotVerifiedError,
    UserService,
    VerificationDeliveryError,
)
from utils import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)

auth_router = APIRouter()

@auth_router.post("/signup", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def signup(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_session)],
    _rate_limit: Annotated[None, Depends(rate_limit_signup)] = None,
):
    service = UserService(db)
    try:
        return await service.create_user(user_in)
    except VerificationDeliveryError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Account created, but verification email delivery failed. Please retry later.",
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account with the provided details",
        ) from None

@auth_router.post("/login", response_model=Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_session)],
    _rate_limit: Annotated[None, Depends(rate_limit_login)] = None,
):
    service = UserService(db)

    try:
        user = await service.authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = str(user.uid)
        extra_claims = {"role": user.role}
        access_token = create_access_token(subject=user_id, extra_claims=extra_claims)
        refresh_token = create_refresh_token(subject=user_id, extra_claims=extra_claims)
        return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")
    
    except HTTPException:
        raise
    except EmailNotVerifiedError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except Exception:
        logger.error("Unexpected error during login")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from None

@auth_router.post("/verify-email", status_code=status.HTTP_200_OK)
async def verify_email(
    verification: EmailVerificationRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    _rate_limit: Annotated[None, Depends(rate_limit_verify_email)] = None,
):
    service = UserService(db)
    success = await service.verify_email(verification.user_id, verification.code)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to verify email with the provided details",
        )
    return {"message": "Email verified successfully"}


@auth_router.post("/resend-verification", status_code=status.HTTP_202_ACCEPTED)
async def resend_verification(
    resend: EmailVerificationResendRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    _rate_limit: Annotated[None, Depends(rate_limit_resend_verification)] = None,
):
    service = UserService(db)
    try:
        await service.resend_verification_email(str(resend.email))
    except Exception:
        logger.error("Unexpected error while processing verification resend")
    return {
        "message": "Request processed. If eligible, verification delivery will be attempted."
    }

@auth_router.post("/refresh", response_model=Token)
async def refresh_token(
    _rate_limit: Annotated[None, Depends(rate_limit_refresh)],
    current_user: Annotated[User, Depends(validate_refresh_token)],
) -> Token:
    user_id = str(current_user.uid)
    extra_claims = {"role": current_user.role}
    new_access = create_access_token(subject=user_id, extra_claims=extra_claims)
    new_refresh = create_refresh_token(subject=user_id, extra_claims=extra_claims)
    return Token(access_token=new_access, refresh_token=new_refresh, token_type="bearer")

@auth_router.get("/me", response_model=UserRead)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return UserRead(
        uid=current_user.uid,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        email_verified=current_user.email_verified
    )

@auth_router.patch(
    "/me",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
)
async def update_my_profile(
    user_update: UserUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_session)],
):

    service = UserService(db)

    try:

        return await service.update_user(
            current_user=current_user,
            user_update=user_update,
        )

    except ValueError as e:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    except Exception:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        )
