"""
Database initialization helpers.
Creates ORM tables asynchronously on startup.
"""
import logging
from app.database.base import Base
from app.database.session import engine

# Import all models to ensure they are registered with SQLAlchemy Base.metadata
from app.models.investigation import Investigation
from app.models.finding import Finding
from app.models.asset import Asset
from app.models.ti_report import TIReport
from app.models.tm_report import TMReport

logger = logging.getLogger(__name__)

async def init_models():
    """Create database tables if they do not exist."""
    try:
        async with engine.begin() as conn:
            # Drop/re-create can be managed here if needed
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Successfully initialized all database tables.")
        print("[DB INIT] Database tables initialized.")
    except Exception as e:
        logger.error(f"Error initializing database tables: {e}")
        print(f"[DB INIT] Error: {e}")
        raise e
