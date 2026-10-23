import asyncio
import os
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, HTTPException, Request, status
from redis.exceptions import ConnectionError as RedisConnectionError


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
os.environ.setdefault("REDIS_URL", "redis://redis.test:6379/0")

from database.db_config import config
from rate_limit import (
    RateLimitAttempt,
    RateLimitRule,
    RedisRateLimitStore,
    enforce_rate_limits,
    get_client_identifier,
)
from redis_client import redis_lifespan


class InMemoryRedis:
    """Small deterministic fake for exercising the Redis store contract."""

    def __init__(self) -> None:
        self.now_ms = 0
        self.values: dict[str, tuple[int, int]] = {}
        self._lock = asyncio.Lock()
        self.scripts: list[str] = []

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | int,
    ) -> object:
        await asyncio.sleep(0)
        async with self._lock:
            self.scripts.append(script)
            if numkeys != 1 or len(keys_and_args) != 3:
                raise AssertionError("unexpected Redis EVAL arguments")
            key = str(keys_and_args[0])
            limit = int(keys_and_args[1])
            window_ms = int(keys_and_args[2])
            count, expires_at = self.values.get(key, (0, self.now_ms + window_ms))
            if self.now_ms >= expires_at:
                count, expires_at = 0, self.now_ms + window_ms
            if count >= limit:
                return [0, max(1, expires_at - self.now_ms)]
            count += 1
            self.values[key] = (count, expires_at)
            return [1, max(1, expires_at - self.now_ms)]


class BrokenRedis:
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | int,
    ) -> object:
        raise RedisConnectionError("redis details must not escape")


def make_request(
    client_host: str,
    forwarded_for: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/auth/login",
            "headers": headers,
            "client": (client_host, 12345),
        }
    )


class ClientIdentificationTests(TestCase):
    def test_spoofed_forwarded_header_is_ignored_for_untrusted_peer(self) -> None:
        request = make_request("203.0.113.10", "198.51.100.7")

        with patch.object(config, "TRUSTED_PROXY_CIDRS", ""):
            self.assertEqual(get_client_identifier(request), "203.0.113.10")

    def test_trusted_proxy_uses_nearest_untrusted_forwarded_address(self) -> None:
        request = make_request(
            "10.0.0.5",
            "192.0.2.44, 198.51.100.9, 10.0.0.4",
        )

        with patch.object(config, "TRUSTED_PROXY_CIDRS", "10.0.0.0/8"):
            self.assertEqual(get_client_identifier(request), "198.51.100.9")

    def test_invalid_forwarded_header_falls_back_to_connected_peer(self) -> None:
        request = make_request("10.0.0.5", "not-an-ip")

        with patch.object(config, "TRUSTED_PROXY_CIDRS", "10.0.0.0/8"):
            self.assertEqual(get_client_identifier(request), "10.0.0.5")


class RedisRateLimitTests(IsolatedAsyncioTestCase):
    async def _consume(self, redis: InMemoryRedis, subject: str) -> None:
        await enforce_rate_limits(
            store=RedisRateLimitStore(redis),
            endpoint="login",
            client_identifier="203.0.113.10",
            subject_identifiers=(subject,),
            client_rule=RateLimitRule(requests=20, window_seconds=60),
            subject_rule=RateLimitRule(requests=2, window_seconds=60),
        )

    async def test_unknown_account_attempts_are_limited_and_expire(self) -> None:
        redis = InMemoryRedis()
        await self._consume(redis, "missing-user")
        await self._consume(redis, "missing-user")

        with self.assertRaises(HTTPException) as raised:
            await self._consume(redis, "missing-user")

        self.assertEqual(
            raised.exception.status_code,
            status.HTTP_429_TOO_MANY_REQUESTS,
        )
        self.assertEqual(raised.exception.headers, {"Retry-After": "60"})
        self.assertEqual(
            raised.exception.detail,
            "Too many requests. Please try again later.",
        )

        redis.now_ms = 60_000
        await self._consume(redis, "missing-user")

    async def test_concurrent_requests_cannot_exceed_limit(self) -> None:
        redis = InMemoryRedis()
        store = RedisRateLimitStore(redis)
        attempt = RateLimitAttempt(
            endpoint="refresh",
            scope="subject",
            identifier_hash="a" * 64,
            rule=RateLimitRule(requests=5, window_seconds=60),
        )

        results = await asyncio.gather(
            *(store.consume((attempt,)) for _ in range(50))
        )

        self.assertEqual(sum(result[0].allowed for result in results), 5)
        self.assertEqual(next(iter(redis.values.values()))[0], 5)

    async def test_store_uses_atomic_increment_and_expiry_script(self) -> None:
        redis = InMemoryRedis()
        store = RedisRateLimitStore(redis)
        attempt = RateLimitAttempt(
            endpoint="verify-email",
            scope="subject",
            identifier_hash="b" * 64,
            rule=RateLimitRule(requests=5, window_seconds=900),
        )

        result = await store.consume((attempt,))

        self.assertTrue(result[0].allowed)
        self.assertEqual(result[0].retry_after, 900)
        self.assertIn("INCR", redis.scripts[0])
        self.assertIn("PEXPIRE", redis.scripts[0])
        self.assertIn("PTTL", redis.scripts[0])

    async def test_different_accounts_do_not_share_subject_limit(self) -> None:
        redis = InMemoryRedis()
        await self._consume(redis, "first-user")
        await self._consume(redis, "first-user")
        await self._consume(redis, "second-user")

    async def test_raw_identifiers_are_not_stored_in_redis_keys(self) -> None:
        redis = InMemoryRedis()
        raw_subject = "private-user@example.test"
        raw_client = "203.0.113.10"

        await enforce_rate_limits(
            store=RedisRateLimitStore(redis),
            endpoint="signup",
            client_identifier=raw_client,
            subject_identifiers=(raw_subject,),
            client_rule=RateLimitRule(10, 60),
            subject_rule=RateLimitRule(3, 60),
        )

        stored_keys = list(redis.values)
        self.assertTrue(stored_keys)
        self.assertTrue(all(raw_subject not in key for key in stored_keys))
        self.assertTrue(all(raw_client not in key for key in stored_keys))

    async def test_backend_error_is_sanitized_and_fails_closed(self) -> None:
        with (
            patch("rate_limit.logger.error") as log_error,
            self.assertRaises(HTTPException) as raised,
        ):
            await enforce_rate_limits(
                store=RedisRateLimitStore(BrokenRedis()),
                endpoint="refresh",
                client_identifier="203.0.113.10",
                subject_identifiers=("secret-refresh-token",),
                client_rule=RateLimitRule(120, 60),
                subject_rule=RateLimitRule(30, 60),
            )

        self.assertEqual(
            raised.exception.status_code,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )
        self.assertEqual(
            raised.exception.detail,
            "Authentication service temporarily unavailable",
        )
        self.assertNotIn("redis details", raised.exception.detail)
        log_error.assert_called_once_with("Rate-limit backend unavailable")


class RedisLifespanTests(IsolatedAsyncioTestCase):
    async def test_lifespan_connects_and_closes_client(self) -> None:
        app = FastAPI()
        client = AsyncMock()

        with patch("redis_client.create_redis_client", return_value=client):
            async with redis_lifespan(app):
                client.ping.assert_awaited_once_with()
                self.assertIs(app.state.redis, client)
                client.aclose.assert_not_awaited()

        client.aclose.assert_awaited_once_with()

    async def test_lifespan_closes_client_when_startup_ping_fails(self) -> None:
        app = FastAPI()
        client = AsyncMock()
        client.ping.side_effect = RedisConnectionError("unavailable")

        with (
            patch("redis_client.create_redis_client", return_value=client),
            self.assertRaises(RedisConnectionError),
        ):
            async with redis_lifespan(app):
                self.fail("lifespan should not start")

        client.aclose.assert_awaited_once_with()
