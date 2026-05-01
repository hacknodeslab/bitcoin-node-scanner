"""
Database connection management for Bitcoin Node Scanner.
"""
import logging
import os
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, event, inspect, text
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


# Stable bigint key used to serialize concurrent `init_db()` callers via
# PostgreSQL's transaction-scoped advisory lock. The exact value is arbitrary;
# what matters is that every process picks the same key. Hand-rolled bigint
# below 2^63 so it fits PostgreSQL's `bigint` parameter.
_INIT_DB_ADVISORY_LOCK_KEY = 7242419823


def init_db() -> bool:
    """
    Initialize the database by creating all tables and applying any
    additive schema migrations.

    DDL is serialized across concurrent processes:
    - PostgreSQL: `pg_advisory_xact_lock` held until commit, so two workers
      hitting startup at the same time can't both issue `ALTER TABLE` and
      race each other.
    - SQLite: the file-level write lock acquired by the surrounding
      transaction is sufficient (single-writer database).

    Returns:
        True if initialization completed; False if no database is configured.

    Raises:
        Any exception raised by the underlying engine — callers should let
        the process fail fast rather than continue against a half-migrated
        schema. (Previously this method swallowed exceptions and returned
        False; that masked migration failures.)
    """
    engine = get_engine()
    if engine is None:
        logger.debug("Database not configured, skipping initialization")
        return False

    db_url = get_database_url() or ""

    with engine.begin() as conn:
        if is_postgresql(db_url):
            conn.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _INIT_DB_ADVISORY_LOCK_KEY},
            )
        Base.metadata.create_all(bind=conn)
        _migrate_schema(conn)

    logger.info("Database tables created successfully")
    return True


def _migrate_schema(conn) -> None:
    """Apply additive, idempotent schema upgrades on pre-existing databases.

    `Base.metadata.create_all` is a no-op for already-existing tables, so when
    we add new columns to a model we need to ALTER TABLE the live schema.
    Keep migrations here narrow and idempotent — guarded by inspector checks
    so re-runs are safe. All DDL runs on the caller-supplied connection so
    `init_db()`'s advisory lock covers it.
    """
    inspector = inspect(conn)
    if "nodes" not in inspector.get_table_names():
        return

    existing_cols = {col["name"] for col in inspector.get_columns("nodes")}

    if "is_example" not in existing_cols:
        # SQLite and PostgreSQL both accept this exact statement.
        if is_sqlite(get_database_url() or ""):
            conn.execute(text(
                "ALTER TABLE nodes ADD COLUMN is_example BOOLEAN NOT NULL DEFAULT 0"
            ))
        else:
            conn.execute(text(
                "ALTER TABLE nodes ADD COLUMN is_example BOOLEAN NOT NULL DEFAULT FALSE"
            ))
        logger.info("Added is_example column to nodes table")

    existing_indexes = {idx["name"] for idx in inspector.get_indexes("nodes")}
    if "idx_nodes_is_example" not in existing_indexes:
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_nodes_is_example ON nodes (is_example)"))


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
