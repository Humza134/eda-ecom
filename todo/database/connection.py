import ssl
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from database.db_config import config


def create_db_ssl_context() -> ssl.SSLContext:
    """Create a verify-full TLS context for PostgreSQL connections."""
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


ssl_context = create_db_ssl_context()

# Create the async engine
engine: AsyncEngine = create_async_engine(
    config.DATABASE_URL,
    connect_args={"ssl": ssl_context},
    echo=True
)

async def init_db() -> None:
    """Initialize the database schema (use for dev or fallback)."""
    async with engine.begin() as conn:
        # if you are using migrations normally, you might skip create_all in production
        await conn.run_sync(SQLModel.metadata.create_all)

# create sessionmaker factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,     # recommended
    autoflush=False,
    future=True,
)

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency-injection for FastAPI: provides an async DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            # optionally commit here or commit in your service/CRUD layer
        except Exception:
            await session.rollback()
            raise
        finally:
            # optional: closing is handled by context manager
            pass
