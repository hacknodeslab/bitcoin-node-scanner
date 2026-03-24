"""
Allow running database CLI as a module.

Usage:
    python -m src.db db-stats
    python -m src.db db-trends --days 30
"""
from .cli import main

if __name__ == "__main__":
    exit(main())
