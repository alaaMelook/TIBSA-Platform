"""
Database connection and session configurations.
Supports dynamic connection to PostgreSQL via DATABASE_URL and SQLite fallback.
"""
import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.config import settings

# Determine the database connection string. Priority:
# 1. Environment variable DATABASE_URL
# 2. Supabase DB URL if constructible (future enhancement)
# 3. SQLite fallback for local development & testing
DATABASE_URL = os.getenv("DATABASE_URL") or "sqlite+aiosqlite:///./tibsa_platform.db"

# Map to async driver for PostgreSQL
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)

# Check if SQLite is being used to pass suitable connect_args
is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

# Create async database engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for query logs in development
    connect_args=connect_args
)

# Async session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_db():
    """Dependency provider for FastAPI route endpoints."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
