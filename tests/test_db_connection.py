"""
Tests for database connection module.
"""
import os
import pytest
from unittest.mock import patch, MagicMock

import src.db.connection as conn_module


@pytest.fixture(autouse=True)
def reset_connection_state():
    """Reset global connection state before and after each test."""
    conn_module._engine = None
    conn_module._SessionLocal = None
    yield
    if conn_module._engine is not None:
        try:
            conn_module._engine.dispose()
        except Exception:
            pass
    conn_module._engine = None
    conn_module._SessionLocal = None


class TestGetDatabaseUrl:
    def test_returns_none_when_not_set(self):
        env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
        with patch.dict(os.environ, env, clear=True):
            assert conn_module.get_database_url() is None

    def test_returns_url_when_set(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            assert conn_module.get_database_url() == "sqlite:///:memory:"


class TestIsDatabaseConfigured:
    def test_false_when_not_configured(self):
        with patch.object(conn_module, "get_database_url", return_value=None):
            assert conn_module.is_database_configured() is False

    def test_true_when_configured(self):
        with patch.object(conn_module, "get_database_url", return_value="sqlite:///:memory:"):
            assert conn_module.is_database_configured() is True


class TestIsSqlite:
    def test_sqlite_urls(self):
        assert conn_module.is_sqlite("sqlite:///:memory:") is True
        assert conn_module.is_sqlite("sqlite:///db.sqlite3") is True

    def test_non_sqlite_urls(self):
        assert conn_module.is_sqlite("postgresql://localhost/db") is False
        assert conn_module.is_sqlite("mysql://localhost/db") is False


class TestIsPostgresql:
    def test_postgresql_urls(self):
        assert conn_module.is_postgresql("postgresql://localhost/db") is True
        assert conn_module.is_postgresql("postgres://localhost/db") is True

    def test_non_postgresql_urls(self):
        assert conn_module.is_postgresql("sqlite:///:memory:") is False
        assert conn_module.is_postgresql("mysql://localhost/db") is False


class TestGetEngine:
    def test_returns_none_when_no_url(self):
        with patch.object(conn_module, "get_database_url", return_value=None):
            engine = conn_module.get_engine()
        assert engine is None

    def test_creates_sqlite_engine(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            engine = conn_module.get_engine()
        assert engine is not None

    def test_returns_cached_engine_on_second_call(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            engine1 = conn_module.get_engine()
            engine2 = conn_module.get_engine()
        assert engine1 is engine2

    def test_handles_connection_failure_gracefully(self):
        with patch.object(conn_module, "get_database_url", return_value="sqlite:///:memory:"):
            with patch("src.db.connection.create_engine", side_effect=Exception("fail")):
                engine = conn_module.get_engine()
        assert engine is None

    def test_generic_db_engine(self):
        """Test the generic (non-sqlite, non-postgresql) engine branch."""
        with patch.object(conn_module, "get_database_url", return_value="mysql+pymysql://u:p@h/db"):
            with patch("src.db.connection.create_engine") as mock_create:
                mock_engine = MagicMock()
                mock_create.return_value = mock_engine
                engine = conn_module.get_engine()
        assert engine is mock_engine


class TestGetSessionFactory:
    def test_returns_none_when_no_engine(self):
        with patch.object(conn_module, "get_engine", return_value=None):
            factory = conn_module.get_session_factory()
        assert factory is None

    def test_creates_session_factory(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            factory = conn_module.get_session_factory()
        assert factory is not None

    def test_returns_cached_factory_on_second_call(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            f1 = conn_module.get_session_factory()
            f2 = conn_module.get_session_factory()
        assert f1 is f2


class TestGetDbSession:
    def test_yields_none_when_not_configured(self):
        with patch.object(conn_module, "get_session_factory", return_value=None):
            with conn_module.get_db_session() as session:
                assert session is None

    def test_yields_session_when_configured(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from src.db.models import Base

        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        with patch.object(conn_module, "get_session_factory", return_value=SessionLocal):
            with conn_module.get_db_session() as session:
                assert session is not None

    def test_rolls_back_on_exception(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from src.db.models import Base

        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        with patch.object(conn_module, "get_session_factory", return_value=SessionLocal):
            with pytest.raises(RuntimeError, match="test rollback"):
                with conn_module.get_db_session() as session:
                    assert session is not None
                    raise RuntimeError("test rollback")


class TestInitDb:
    def test_returns_false_when_not_configured(self):
        with patch.object(conn_module, "get_engine", return_value=None):
            result = conn_module.init_db()
        assert result is False

    def test_creates_tables_with_sqlite(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            result = conn_module.init_db()
        assert result is True

    def test_returns_false_on_error(self):
        from src.db.models import Base
        mock_engine = MagicMock()

        with patch.object(conn_module, "get_engine", return_value=mock_engine):
            with patch.object(Base.metadata, "create_all", side_effect=Exception("failed")):
                result = conn_module.init_db()
        assert result is False


class TestCloseDb:
    def test_closes_existing_engine(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
            conn_module.get_engine()
            assert conn_module._engine is not None
            conn_module.close_db()
        assert conn_module._engine is None
        assert conn_module._SessionLocal is None

    def test_safe_when_no_engine(self):
        conn_module._engine = None
        conn_module._SessionLocal = None
        conn_module.close_db()  # Should not raise


class TestGetDbType:
    def test_returns_none_when_not_configured(self):
        with patch.object(conn_module, "get_database_url", return_value=None):
            assert conn_module.get_db_type() is None

    def test_returns_sqlite(self):
        with patch.object(conn_module, "get_database_url", return_value="sqlite:///:memory:"):
            assert conn_module.get_db_type() == "sqlite"

    def test_returns_postgresql(self):
        with patch.object(conn_module, "get_database_url", return_value="postgresql://h/db"):
            assert conn_module.get_db_type() == "postgresql"

    def test_returns_other(self):
        with patch.object(conn_module, "get_database_url", return_value="mysql://h/db"):
            assert conn_module.get_db_type() == "other"
