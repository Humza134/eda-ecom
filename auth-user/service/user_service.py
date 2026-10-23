# services/user_service.py
from datetime import datetime, timedelta, timezone
import hmac
import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from email.message import EmailMessage
import aiosmtplib

from database.db_config import config
from utils import (
    generate_email_verification_code,
    hash_email_verification_code,
    hash_password,
    verify_password,
)
from model.user_model import User, UserCreate, UserRead, UserUpdate  # adjust path according to your project


class EmailNotVerifiedError(Exception):
    """Raised when valid credentials belong to an unverified account."""


class VerificationDeliveryError(Exception):
    """Raised when an OTP could not be delivered."""


logger = logging.getLogger(__name__)


class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _send_verification_email(self, to_email: str, code: str) -> None:
        # sender = os.getenv("EMAIL_USER")
        # password = os.getenv("EMAIL_PASS")
        # hostname = os.getenv("SMTP_HOST", "smtp.gmail.com")
        # port = int(os.getenv("SMTP_PORT", "587"))

        sender = config.EMAIL_USER
        password = config.EMAIL_PASS
        hostname = config.SMTP_HOST
        port = config.SMTP_PORT

        if not sender or not password:
            raise VerificationDeliveryError

        message = EmailMessage()
        message["From"] = sender
        message["To"] = to_email
        message["Subject"] = "Email Verification Code"
        body = f"Your verification code is: {code}"
        message.set_content(body)

        try:
            await aiosmtplib.send(
                message,
                hostname=hostname,
                port=port,
                username=sender,
                password=password,
                start_tls=True,
            )
        except Exception:
            raise VerificationDeliveryError from None

    @staticmethod
    def _clear_verification(user: User) -> None:
        user.email_verification_code_hash = None
        user.email_verification_expires_at = None
        user.email_verification_attempts = 0

    @staticmethod
    def _issue_verification(user: User) -> tuple[str, str]:
        code = generate_email_verification_code(length=6)
        code_hash = hash_email_verification_code(user.uid, code)
        user.email_verification_code_hash = code_hash
        user.email_verification_attempts = 0
        user.email_verification_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=config.OTP_EXPIRY_SECONDS
        )
        return code, code_hash

    async def _invalidate_verification_if_current(
        self,
        user_id: UUID,
        expected_hash: str,
    ) -> None:
        """Invalidate only the failed delivery, not a newer concurrently issued OTP."""
        try:
            result = await self.db.exec(
                select(User).where(User.uid == user_id).with_for_update()
            )
            user = result.first()
            if user is not None and hmac.compare_digest(
                user.email_verification_code_hash or "",
                expected_hash,
            ):
                self._clear_verification(user)
                self.db.add(user)
                await self.db.commit()
        except Exception:
            await self.db.rollback()
            logger.error("Unable to invalidate OTP after delivery failure")

    async def create_user(self, user_in: UserCreate) -> UserRead:
        # check existing user
        statement = select(User).where((User.email == user_in.email) | (User.username == user_in.username))
        # All database I/O is now awaited
        result = await self.db.exec(statement)
        existing = result.first()
        if existing:
            raise ValueError("User with this email or username already exists")

        hashed_pw = await hash_password(user_in.password)
        user = User(
            username=user_in.username,
            email=user_in.email,
            hashed_password=hashed_pw,
            role="user",
            email_verified=False
        )

        code, code_hash = self._issue_verification(user)

        try:
            self.db.add(user)
            await self.db.commit()
            await self.db.refresh(user)
        except Exception:
            await self.db.rollback()
            raise

        try:
            await self._send_verification_email(to_email=user.email, code=code)
        except VerificationDeliveryError:
            logger.error("Verification email delivery failed during signup")
            await self._invalidate_verification_if_current(user.uid, code_hash)
            raise

        return UserRead(
            uid=user.uid,
            username=user.username,
            email=user.email,
            role=user.role,
            email_verified=user.email_verified
        )

    async def verify_email(self, user_id: UUID, code: str) -> bool:
        try:
            result = await self.db.exec(
                select(User).where(User.uid == user_id).with_for_update()
            )
            user = result.first()
            if user is None or user.email_verified:
                return False

            expires_at = user.email_verification_expires_at
            code_hash = user.email_verification_code_hash
            if expires_at is None or code_hash is None:
                return False

            if expires_at <= datetime.now(timezone.utc):
                self._clear_verification(user)
                self.db.add(user)
                await self.db.commit()
                return False

            submitted_hash = hash_email_verification_code(user.uid, code)
            if not hmac.compare_digest(code_hash, submitted_hash):
                user.email_verification_attempts += 1
                if user.email_verification_attempts >= config.OTP_MAX_ATTEMPTS:
                    self._clear_verification(user)
                self.db.add(user)
                await self.db.commit()
                return False

            user.email_verified = True
            self._clear_verification(user)
            self.db.add(user)
            await self.db.commit()
            await self.db.refresh(user)
        except Exception:
            await self.db.rollback()
            raise

        return True

    async def resend_verification_email(self, email: str) -> None:
        """Issue a replacement OTP without revealing whether the account exists."""
        result = await self.db.exec(
            select(User)
            .where(func.lower(User.email) == email.strip().casefold())
            .with_for_update()
        )
        user = result.first()
        if user is None or user.email_verified:
            return

        code, code_hash = self._issue_verification(user)
        try:
            self.db.add(user)
            await self.db.commit()
            await self.db.refresh(user)
        except Exception:
            await self.db.rollback()
            raise

        try:
            await self._send_verification_email(user.email, code)
        except VerificationDeliveryError:
            logger.error("Verification email delivery failed during resend")
            await self._invalidate_verification_if_current(user.uid, code_hash)

    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        statement = select(User).where(User.username == username)
        result = await self.db.exec(statement)
        user = result.first()
        if not user:
            return None
        if not await verify_password(password, user.hashed_password):
            return None
        if not user.email_verified:
            raise EmailNotVerifiedError

        return user

    async def update_user(
        self,
        current_user: User,
        user_update: UserUpdate,
    ) -> UserRead:

        update_data = user_update.model_dump(exclude_unset=True)

        # Nothing to update
        if not update_data:
            raise ValueError("No fields provided for update")

        # ----------------------------
        # Username
        # ----------------------------
        if "username" in update_data:

            statement = select(User).where(
                User.username == update_data["username"],
                User.uid != current_user.uid,
            )

            result = await self.db.exec(statement)

            if result.first():
                raise ValueError("Username already exists")

            current_user.username = update_data["username"]

        # ----------------------------
        # Email
        # ----------------------------
        if "email" in update_data:

            statement = select(User).where(
                User.email == update_data["email"],
                User.uid != current_user.uid,
            )

            result = await self.db.exec(statement)

            if result.first():
                raise ValueError("Email already exists")

            current_user.email = update_data["email"]

            # Email must be verified again
            current_user.email_verified = False

            code, _ = self._issue_verification(current_user)

            try:
                await self._send_verification_email(
                current_user.email,
                code,
            )
            except VerificationDeliveryError:
                raise ValueError("Failed to send verification email. Please try again later.")

        # ----------------------------
        # Password
        # ----------------------------
        if "password" in update_data:

            current_user.hashed_password = await hash_password(
                update_data["password"]
            )

        # ----------------------------
        # Update timestamp
        # ----------------------------
        current_user.updated_at = datetime.now(timezone.utc)

        try:

            self.db.add(current_user)

            await self.db.commit()

            await self.db.refresh(current_user)

        except Exception:

            await self.db.rollback()

            raise

        return UserRead(
            uid=current_user.uid,
            username=current_user.username,
            email=current_user.email,
            role=current_user.role,
            email_verified=current_user.email_verified,
        )

