import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import sys
from types import ModuleType
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request, status


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")
os.environ.setdefault("PRIVATE_KEY_PATH", "unused-private.pem")
os.environ.setdefault("PUBLIC_KEY_PATH", "unused-public.pem")
os.environ.setdefault("JWT_KEY_ID", "test-key")
os.environ.setdefault("JWT_ISSUER", "auth-user.test")
os.environ.setdefault("JWT_ACCESS_AUDIENCE", "auth-user-access.test")
os.environ.setdefault("JWT_REFRESH_AUDIENCE", "auth-user-refresh.test")
os.environ.setdefault("EMAIL_USER", "test@example.com")
os.environ.setdefault("EMAIL_PASS", "unused")
os.environ.setdefault("SMTP_HOST", "smtp.test")
os.environ.setdefault("SMTP_PORT", "587")
os.environ.setdefault("RATE_LIMIT_KEY_SECRET", "test-rate-limit-secret-at-least-32-bytes")
os.environ.setdefault("OTP_HMAC_SECRET", "test-otp-hmac-secret-at-least-32-bytes")
os.environ.setdefault("REDIS_URL", "redis://redis.test:6379/0")


if "utils" not in sys.modules:
    utils_stub = ModuleType("utils")
    utils_stub.create_access_token = lambda *args, **kwargs: "access-token"
    utils_stub.create_refresh_token = lambda *args, **kwargs: "refresh-token"
    utils_stub.decode_token = lambda *args, **kwargs: {}
    utils_stub.generate_email_verification_code = lambda length=6: "123456"
    utils_stub.hash_email_verification_code = lambda user_id, code: _otp_hash(user_id, code)
    utils_stub.hash_password = AsyncMock(return_value="hashed-password")
    utils_stub.verify_password = AsyncMock(return_value=True)
    sys.modules["utils"] = utils_stub


from database.db_config import config
from dependencies import rate_limit_resend_verification
from model.user_model import (
    EmailVerificationRequest,
    EmailVerificationResendRequest,
    User,
    UserCreate,
)
from router.user_routes import auth_router, resend_verification, verify_email
from service.user_service import UserService, VerificationDeliveryError


_TEST_HMAC_KEY = b"isolated-test-key-with-at-least-32-bytes"


def _otp_hash(user_id: UUID, code: str) -> str:
    return hmac.new(
        _TEST_HMAC_KEY,
        f"email-verification\0{user_id}\0{code}".encode(),
        hashlib.sha256,
    ).hexdigest()


class _Result:
    def __init__(self, user: User | None) -> None:
        self._user = user

    def first(self) -> User | None:
        return self._user


class _Store:
    def __init__(self, user: User | None) -> None:
        self.user = user
        self.lock = asyncio.Lock()


class _Session:
    """Transaction fake that models PostgreSQL's SELECT FOR UPDATE serialization."""

    def __init__(self, store: _Store) -> None:
        self.store = store
        self._locked = False

    async def exec(self, statement: object) -> _Result:
        await self.store.lock.acquire()
        self._locked = True
        return _Result(self.store.user)

    def add(self, user: User) -> None:
        self.store.user = user

    async def commit(self) -> None:
        self._release()

    async def rollback(self) -> None:
        self._release()

    async def refresh(self, user: User) -> None:
        return None

    def _release(self) -> None:
        if self._locked:
            self._locked = False
            self.store.lock.release()


def _user(code: str = "123456", *, expires_in: int = 600) -> User:
    user = User(
        uid=uuid4(),
        username="alice",
        email="alice@example.com",
        hashed_password="hashed-password",
    )
    user.email_verification_code_hash = _otp_hash(user.uid, code)
    user.email_verification_expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=expires_in
    )
    return user


class VerificationServiceTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.hash_patch = patch(
            "service.user_service.hash_email_verification_code",
            side_effect=_otp_hash,
        )
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)

    async def test_valid_code_is_single_use(self) -> None:
        store = _Store(_user())

        self.assertNotEqual(store.user.email_verification_code_hash, "123456")

        self.assertTrue(await UserService(_Session(store)).verify_email(store.user.uid, "123456"))
        self.assertFalse(await UserService(_Session(store)).verify_email(store.user.uid, "123456"))
        self.assertTrue(store.user.email_verified)
        self.assertIsNone(store.user.email_verification_code_hash)

    async def test_invalid_and_expired_codes_are_rejected(self) -> None:
        invalid_store = _Store(_user())
        self.assertFalse(
            await UserService(_Session(invalid_store)).verify_email(
                invalid_store.user.uid, "000000"
            )
        )
        self.assertEqual(invalid_store.user.email_verification_attempts, 1)

        expired_store = _Store(_user(expires_in=-1))
        self.assertFalse(
            await UserService(_Session(expired_store)).verify_email(
                expired_store.user.uid, "123456"
            )
        )
        self.assertIsNone(expired_store.user.email_verification_code_hash)

    async def test_attempt_limit_persists_and_invalidates_code(self) -> None:
        store = _Store(_user())
        with patch.object(config, "OTP_MAX_ATTEMPTS", 2):
            self.assertFalse(await UserService(_Session(store)).verify_email(store.user.uid, "000000"))
            self.assertFalse(await UserService(_Session(store)).verify_email(store.user.uid, "000001"))

        self.assertIsNone(store.user.email_verification_code_hash)
        self.assertEqual(store.user.email_verification_attempts, 0)
        self.assertFalse(await UserService(_Session(store)).verify_email(store.user.uid, "123456"))

    async def test_resend_invalidates_previous_code(self) -> None:
        store = _Store(_user(code="111111"))
        service = UserService(_Session(store))
        with (
            patch("service.user_service.generate_email_verification_code", return_value="222222"),
            patch.object(service, "_send_verification_email", new=AsyncMock()) as send_email,
        ):
            await service.resend_verification_email("ALICE@example.com")

        send_email.assert_awaited_once_with("alice@example.com", "222222")
        self.assertFalse(await UserService(_Session(store)).verify_email(store.user.uid, "111111"))
        self.assertTrue(await UserService(_Session(store)).verify_email(store.user.uid, "222222"))

    async def test_concurrent_verification_allows_only_one_success(self) -> None:
        store = _Store(_user())
        results = await asyncio.gather(
            UserService(_Session(store)).verify_email(store.user.uid, "123456"),
            UserService(_Session(store)).verify_email(store.user.uid, "123456"),
        )
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 1)

    async def test_signup_smtp_failure_is_reported_and_code_invalidated(self) -> None:
        store = _Store(None)
        service = UserService(_Session(store))
        with (
            patch("service.user_service.generate_email_verification_code", return_value="123456"),
            patch("service.user_service.hash_password", new=AsyncMock(return_value="hashed")),
            patch.object(
                service,
                "_send_verification_email",
                new=AsyncMock(side_effect=VerificationDeliveryError),
            ),
            self.assertRaises(VerificationDeliveryError),
        ):
            await service.create_user(
                UserCreate(username="alice", email="alice@example.com", password="secret")
            )

        self.assertIsNotNone(store.user)
        self.assertIsNone(store.user.email_verification_code_hash)


class VerificationRouteTests(IsolatedAsyncioTestCase):
    async def test_verify_uses_json_body_and_safe_failure(self) -> None:
        app = FastAPI()
        app.include_router(auth_router, prefix="/auth")
        operation = app.openapi()["paths"]["/auth/verify-email"]["post"]
        self.assertNotIn("parameters", operation)
        self.assertEqual(
            operation["requestBody"]["content"]["application/json"]["schema"],
            {"$ref": "#/components/schemas/EmailVerificationRequest"},
        )

        request = EmailVerificationRequest(user_id=uuid4(), code="123456")
        with (
            patch.object(UserService, "verify_email", new=AsyncMock(return_value=False)),
            self.assertRaises(HTTPException) as raised,
        ):
            await verify_email(request, object(), None)
        self.assertEqual(raised.exception.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("code", raised.exception.detail.casefold())

    async def test_resend_response_does_not_enumerate_accounts_or_claim_delivery(self) -> None:
        request = EmailVerificationResendRequest(email="alice@example.com")
        responses = []
        for outcome in (None, RuntimeError("smtp details")):
            with patch.object(
                UserService,
                "resend_verification_email",
                new=AsyncMock(side_effect=outcome),
            ):
                responses.append(await resend_verification(request, object(), None))

        self.assertEqual(responses[0], responses[1])
        self.assertNotIn("sent", responses[0]["message"].casefold())
        self.assertNotIn("alice", str(responses[0]).casefold())

    async def test_resend_cooldown_reuses_shared_rate_limiter(self) -> None:
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/auth/resend-verification",
                "headers": [],
                "client": ("203.0.113.10", 12345),
                "app": FastAPI(),
            }
        )
        resend = EmailVerificationResendRequest(email="alice@example.com")
        with patch("dependencies._enforce_auth_rate_limit", new=AsyncMock()) as enforce:
            await rate_limit_resend_verification(request, resend)

        enforce.assert_awaited_once()
        kwargs = enforce.await_args.kwargs
        self.assertEqual(kwargs["endpoint"], "resend-verification")
        self.assertEqual(kwargs["subject_requests"], config.RESEND_OTP_ACCOUNT_RATE_LIMIT)
        self.assertEqual(kwargs["window_seconds"], config.RESEND_OTP_COOLDOWN_SECONDS)


class VerificationSchemaTests(TestCase):
    def test_code_requires_exactly_six_digits(self) -> None:
        for invalid in ("12345", "1234567", "abcdef", "12 456"):
            with self.assertRaises(ValueError):
                EmailVerificationRequest(user_id=uuid4(), code=invalid)
