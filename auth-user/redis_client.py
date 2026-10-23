from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from database.db_config import config


def create_redis_client() -> Redis:
    return Redis.from_url(
        config.REDIS_URL.get_secret_value(),
        decode_responses=False,
        health_check_interval=30,
        socket_connect_timeout=config.REDIS_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=config.REDIS_SOCKET_TIMEOUT_SECONDS,
    )


@asynccontextmanager
async def redis_lifespan(app: FastAPI) -> AsyncIterator[None]:
    client = create_redis_client()
    try:
        await client.ping()
        app.state.redis = client
        yield
    finally:
        await client.aclose()
