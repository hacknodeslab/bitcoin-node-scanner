#!/usr/bin/env python3
"""
Database migration script for Bitcoin Node Scanner.

Usage:
    python scripts/migrate.py upgrade      # Apply all pending migrations
    python scripts/migrate.py downgrade    # Rollback last migration
    python scripts/migrate.py current      # Show current revision
    python scripts/migrate.py history      # Show migration history
    python scripts/migrate.py init         # Create tables directly (without Alembic)
"""
import argparse
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_alembic_command(command: str, revision: str = None):
    """Run an Alembic command."""
    try:
        from alembic.config import Config
        from alembic import command as alembic_cmd

        # Get the alembic.ini path
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        alembic_ini = os.path.join(project_root, "alembic.ini")

        if not os.path.exists(alembic_ini):
            print(f"Error: alembic.ini not found at {alembic_ini}")
            sys.exit(1)

        alembic_cfg = Config(alembic_ini)

        if command == "upgrade":
            target = revision or "head"
            alembic_cmd.upgrade(alembic_cfg, target)
            print(f"Successfully upgraded to {target}")

        elif command == "downgrade":
            target = revision or "-1"
            alembic_cmd.downgrade(alembic_cfg, target)
            print(f"Successfully downgraded to {target}")

        elif command == "current":
            alembic_cmd.current(alembic_cfg, verbose=True)

        elif command == "history":
            alembic_cmd.history(alembic_cfg, verbose=True)

        elif command == "heads":
            alembic_cmd.heads(alembic_cfg, verbose=True)

    except ImportError:
        print("Error: Alembic is not installed. Run: pip install alembic")
        sys.exit(1)


def init_db():
    """Initialize database by creating all tables directly."""
    from src.db.connection import init_db as db_init, is_database_configured

    if not is_database_configured():
        print("Error: DATABASE_URL environment variable is not set")
        print("Set it to your PostgreSQL or SQLite connection string:")
        print("  export DATABASE_URL=postgresql://user:pass@localhost/dbname")
        print("  export DATABASE_URL=sqlite:///./bitcoin_scanner.db")
        sys.exit(1)

    if db_init():
        print("Database tables created successfully")
    else:
        print("Failed to create database tables")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Database migration tool for Bitcoin Node Scanner"
    )
    parser.add_argument(
        "command",
        choices=["upgrade", "downgrade", "current", "history", "heads", "init"],
        help="Migration command to run"
    )
    parser.add_argument(
        "--revision", "-r",
        help="Target revision (for upgrade/downgrade)",
        default=None
    )

    args = parser.parse_args()

    # Check for DATABASE_URL
    if not os.getenv("DATABASE_URL"):
        print("Warning: DATABASE_URL environment variable is not set")
        if args.command != "init":
            print("Using default: sqlite:///./bitcoin_scanner.db")
            os.environ["DATABASE_URL"] = "sqlite:///./bitcoin_scanner.db"

    if args.command == "init":
        init_db()
    else:
        run_alembic_command(args.command, args.revision)


if __name__ == "__main__":
    main()
