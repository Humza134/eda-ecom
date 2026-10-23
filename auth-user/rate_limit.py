import hashlib
import hmac
import logging
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from math import ceil
from typing import Protocol, Sequence

from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError

from database.db_config import config


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitRule:
    requests: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimitAttempt:
    endpoint: str
    scope: str
    identifier_hash: str
    rule: RateLimitRule


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int


class RateLimitStore(Protocol):
    async def consume(
        self,
        attempts: Sequence[RateLimitAttempt],
    ) -> list[RateLimitResult]: ...


class RedisEvalClient(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | int,
    ) -> object: ...


class RedisRateLimitStore:
    """Atomic fixed-window counters shared by all app workers and containers."""

    _CONSUME_SCRIPT = """
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        local limit = tonumber(ARGV[1])
        local window_ms = tonumber(ARGV[2])

        if current >= limit then
            local ttl = redis.call('PTTL', KEYS[1])
            if ttl < 1 then
                redis.call('PEXPIRE', KEYS[1], window_ms)
                ttl = window_ms
            end
            return {0, ttl}
        end

        current = redis.call('INCR', KEYS[1])
        if current == 1 then
            redis.call('PEXPIRE', KEYS[1], window_ms)
        end

        local ttl = redis.call('PTTL', KEYS[1])
        if ttl < 1 then
            redis.call('PEXPIRE', KEYS[1], window_ms)
            ttl = window_ms
        end
        return {1, ttl}
    """

    def __init__(self, client: RedisEvalClient) -> None:
        self._client = client

    @staticmethod
    def _key(attempt: RateLimitAttempt) -> str:
        return (
            f"{config.REDIS_RATE_LIMIT_KEY_PREFIX}:"
            f"{attempt.endpoint}:{attempt.scope}:{attempt.identifier_hash}"
        )

    async def consume(
        self,
        attempts: Sequence[RateLimitAttempt],
    ) -> list[RateLimitResult]:
        results: list[RateLimitResult] = []
        for attempt in attempts:
            raw_result = await self._client.eval(
                self._CONSUME_SCRIPT,
                1,
                self._key(attempt),
                attempt.rule.requests,
                attempt.rule.window_seconds * 1000,
            )
            if not isinstance(raw_result, (list, tuple)) or len(raw_result) != 2:
                raise RedisError("Unexpected rate-limit script response")
            allowed = int(raw_result[0]) == 1
            retry_after = max(1, ceil(int(raw_result[1]) / 1000))
            results.append(
                RateLimitResult(allowed=allowed, retry_after=retry_after)
            )
            if not allowed:
                break
        return results


def get_client_identifier(request: Request) -> str:
    peer_host = request.client.host if request.client is not None else "unknown"
    try:
        peer_ip = ip_address(peer_host)
    except ValueError:
        return peer_host

    trusted_networks = tuple(
        ip_network(item.strip(), strict=False)
        for item in config.TRUSTED_PROXY_CIDRS.split(",")
        if item.strip()
    )
    if not any(peer_ip in network for network in trusted_networks):
        return peer_ip.compressed

    forwarded_for = request.headers.get("x-forwarded-for")
    if not forwarded_for:
        return peer_ip.compressed

    try:
        forwarded_ips = [
            ip_address(item.strip()) for item in forwarded_for.split(",")
        ]
    except ValueError:
        return peer_ip.compressed

    for candidate in reversed(forwarded_ips):
        if not any(candidate in network for network in trusted_networks):
            return candidate.compressed
    return forwarded_ips[0].compressed if forwarded_ips else peer_ip.compressed


def _hash_identifier(scope: str, identifier: str) -> str:
    secret = config.RATE_LIMIT_KEY_SECRET.get_secret_value().encode("utf-8")
    message = f"{scope}\0{identifier}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


async def enforce_rate_limits(
    *,
    store: RateLimitStore,
    endpoint: str,
    client_identifier: str,
    subject_identifiers: Sequence[str],
    client_rule: RateLimitRule,
    subject_rule: RateLimitRule,
) -> None:
    attempts = [
        RateLimitAttempt(
            endpoint=endpoint,
            scope="client",
            identifier_hash=_hash_identifier("client", client_identifier),
            rule=client_rule,
        ),
    ]
    attempts.extend(
        RateLimitAttempt(
            endpoint=endpoint,
            scope="subject",
            identifier_hash=_hash_identifier("subject", identifier),
            rule=subject_rule,
        )
        for identifier in subject_identifiers
    )
    try:
        results = await store.consume(attempts)
    except RedisError:
        logger.error("Rate-limit backend unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable",
        ) from None

    exceeded = [result.retry_after for result in results if not result.allowed]
    if exceeded:
        retry_after = max(1, ceil(max(exceeded)))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
