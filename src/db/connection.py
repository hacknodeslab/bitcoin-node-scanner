"""
Database connection management for Bitcoin Node Scanner.
"""
import logging
import os
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

logger = logging.getLogger(__name__)

# Global engine instance
_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None


def get_database_url() -> Optional[str]:
    """Get database URL from environment variable."""
    return os.getenv("DATABASE_URL")


def is_database_configured() -> bool:
    """Check if database is configured via environment variable."""
    return get_database_url() is not None


def is_sqlite(url: str) -> bool:
    """Check if the database URL points to SQLite."""
    return url.startswith("sqlite")


def is_postgresql(url: str) -> bool:
    """Check if the database URL points to PostgreSQL."""
    return url.startswith("postgresql") or url.startswith("postgres")


def get_engine() -> Optional[Engine]:
    """
    Get or create the database engine.

    Returns None if DATABASE_URL is not configured.
    Uses connection pooling with pool_pre_ping for stale connection handling.
    """
    global _engine

    if _engine is not None:
        return _engine

    database_url = get_database_url()
    if not database_url:
        logger.debug("DATABASE_URL not configured, running in file-only mode")
        return None

    try:
        # Configure engine based on database type
        if is_sqlite(database_url):
            # SQLite configuration
            _engine = create_engine(
                database_url,
                echo=False,
                connect_args={"check_same_thread": False},
            )
            # Enable foreign key support for SQLite
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

            logger.info(f"Connected to SQLite database")
        elif is_postgresql(database_url):
            # PostgreSQL configuration with connection pooling
            _engine = create_engine(
                database_url,
                echo=False,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
            )
            logger.info(f"Connected to PostgreSQL database")
        else:
            # Generic configuration
            _engine = create_engine(
                database_url,
                echo=False,
                pool_pre_ping=True,
            )
            logger.info(f"Connected to database")

        return _engine

    except Exception as e:
        logger.warning(f"Failed to connect to database: {e}. Running in file-only mode.")
        return None


def get_session_factory() -> Optional[sessionmaker]:
    """Get or create the session factory."""
    global _SessionLocal

    if _SessionLocal is not None:
        return _SessionLocal

    engine = get_engine()
    if engine is None:
        return None

    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return _SessionLocal


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions with automatic transaction handling.

    Yields a Session and handles commit/rollback automatically.
    Yields None if database is not configured.

    Usage:
        with get_db_session() as session:
            if session:
                # Database operations
                session.add(node)
    """
    SessionLocal = get_session_factory()

    if SessionLocal is None:
        yield None
        return

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database transaction failed: {e}")
        raise
    finally:
        session.close()


def init_db() -> bool:
    """
    Initialize the database by creating all tables.

    Returns True if successful, False if database is not configured.
    """
    engine = get_engine()
    if engine is None:
        logger.debug("Database not configured, skipping initialization")
        return False

    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        return False


def close_db() -> None:
    """Close database connection and cleanup."""
    global _engine, _SessionLocal

    if _engine is not None:
        _engine.dispose()
        _engine = None
        _SessionLocal = None
        logger.debug("Database connection closed")


def get_db_type() -> Optional[str]:
    """
    Get the type of database configured.

    Returns 'sqlite', 'postgresql', or None if not configured.
    """
    database_url = get_database_url()
    if database_url is None:
        return None
    if is_sqlite(database_url):
        return "sqlite"
    if is_postgresql(database_url):
        return "postgresql"
    return "other"
