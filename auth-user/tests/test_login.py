import os
import sys
from types import ModuleType, SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from fastapi.routing import APIRoute

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost/test",
)
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

# Login route tests do not exercise password hashing, JWT cryptography, or key loading.
# Supplying this narrow module stub keeps the tests isolated from local key files.
utils_stub = ModuleType("utils")
utils_stub.create_access_token = MagicMock()
utils_stub.create_refresh_token = MagicMock()
utils_stub.decode_token = MagicMock()
utils_stub.generate_email_verification_code = MagicMock()
utils_stub.hash_email_verification_code = MagicMock()
utils_stub.hash_password = AsyncMock()
utils_stub.verify_password = AsyncMock()
sys.modules.setdefault("utils", utils_stub)

from router.user_routes import auth_router, login
from service.user_service import EmailNotVerifiedError, UserService


class LoginRouteTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.db = MagicMock()

    async def _assert_invalid_credentials(
        self,
        *,
        username: str,
        password: str,
    ) -> None:
        form_data = SimpleNamespace(username=username, password=password)

        with patch.object(
            UserService,
            "authenticate_user",
            new=AsyncMock(return_value=None),
        ) as authenticate_user:
            with self.assertRaises(HTTPException) as raised:
                await login(form_data, self.db)

        self.assertEqual(raised.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(raised.exception.detail, "Invalid username or password")
        self.assertEqual(
            raised.exception.headers,
            {"WWW-Authenticate": "Bearer"},
        )
        authenticate_user.assert_awaited_once_with(username, password)
        self.assertNotIn(password, str(raised.exception.detail))

    async def test_invalid_username_returns_401(self) -> None:
        await self._assert_invalid_credentials(
            username="missing-user",
            password="not-a-real-password",
        )

    async def test_invalid_password_returns_401(self) -> None:
        await self._assert_invalid_credentials(
            username="known-user",
            password="wrong-secret-password",
        )

    async def test_valid_credentials_preserve_successful_login(self) -> None:
        user_id = uuid4()
        user = SimpleNamespace(uid=user_id, role="user")
        form_data = SimpleNamespace(username="known-user", password="valid-password")

        with (
            patch.object(
                UserService,
                "authenticate_user",
                new=AsyncMock(return_value=user),
            ),
            patch(
                "router.user_routes.create_access_token",
                return_value="access-token",
            ) as create_access_token,
            patch(
                "router.user_routes.create_refresh_token",
                return_value="refresh-token",
            ) as create_refresh_token,
        ):
            response = await login(form_data, self.db)

        self.assertEqual(response.access_token, "access-token")
        self.assertEqual(response.refresh_token, "refresh-token")
        self.assertEqual(response.token_type, "bearer")
        expected_claims = {"role": "user"}
        create_access_token.assert_called_once_with(
            subject=str(user_id),
            extra_claims=expected_claims,
        )
        create_refresh_token.assert_called_once_with(
            subject=str(user_id),
            extra_claims=expected_claims,
        )

    async def test_unverified_account_does_not_reveal_account_state(self) -> None:
        form_data = SimpleNamespace(
            username="known-user",
            password="valid-password",
        )

        with (
            patch.object(
                UserService,
                "authenticate_user",
                new=AsyncMock(side_effect=EmailNotVerifiedError),
            ),
            self.assertRaises(HTTPException) as raised,
        ):
            await login(form_data, self.db)

        self.assertEqual(raised.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(raised.exception.detail, "Invalid username or password")
        self.assertEqual(
            raised.exception.headers,
            {"WWW-Authenticate": "Bearer"},
        )

    async def test_unexpected_error_returns_sanitized_500_and_safe_log(self) -> None:
        password = "sensitive-password"
        internal_message = f"database failed while handling {password}"
        form_data = SimpleNamespace(username="known-user", password=password)

        with (
            patch.object(
                UserService,
                "authenticate_user",
                new=AsyncMock(side_effect=RuntimeError(internal_message)),
            ),
            patch("router.user_routes.logger.error") as log_error,
            self.assertRaises(HTTPException) as raised,
        ):
            await login(form_data, self.db)

        self.assertEqual(
            raised.exception.status_code,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        self.assertEqual(raised.exception.detail, "Internal Server Error")
        self.assertNotIn(password, str(raised.exception.detail))
        self.assertNotIn(internal_message, str(raised.exception.detail))
        log_error.assert_called_once_with("Unexpected error during login")
        logged_values = " ".join(str(value) for value in log_error.call_args.args)
        self.assertNotIn(password, logged_values)
        self.assertNotIn(internal_message, logged_values)

    async def test_intended_http_exception_is_preserved(self) -> None:
        intended = HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Retry later")
        form_data = SimpleNamespace(username="known-user", password="password")

        with patch.object(
            UserService,
            "authenticate_user",
            new=AsyncMock(side_effect=intended),
        ):
            with self.assertRaises(HTTPException) as raised:
                await login(form_data, self.db)

        self.assertIs(raised.exception, intended)


class AuthRouteProtectionTests(IsolatedAsyncioTestCase):
    async def test_all_sensitive_routes_have_rate_limit_dependencies(self) -> None:
        expected = {
            "/signup": "rate_limit_signup",
            "/login": "rate_limit_login",
            "/verify-email": "rate_limit_verify_email",
            "/resend-verification": "rate_limit_resend_verification",
            "/refresh": "rate_limit_refresh",
        }

        routes = {
            route.path: route
            for route in auth_router.routes
            if isinstance(route, APIRoute)
        }
        for path, dependency_name in expected.items():
            dependency_names = {
                dependency.call.__name__
                for dependency in routes[path].dependant.dependencies
            }
            self.assertIn(dependency_name, dependency_names)

    async def test_signup_body_contract_remains_user_create(self) -> None:
        app = FastAPI()
        app.include_router(auth_router, prefix="/auth")

        request_schema = app.openapi()["paths"]["/auth/signup"]["post"][
            "requestBody"
        ]["content"]["application/json"]["schema"]

        self.assertEqual(
            request_schema,
            {"$ref": "#/components/schemas/UserCreate"},
        )
