"""Confine CLI-supplied file paths to an allowed directory.

Every command that reads or writes a file named on its command line goes
through here, so a path injected into an automated invocation (e.g. an LLM
agent steered by untrusted content into `--ips ~/.ssh/known_hosts` or
`--json ~/.bashrc`) cannot reach outside the project's data directories.

Two roots, both overridable by the operator's environment (never by a CLI
argument):

- ``INPUT_DIR``  (default ``data``):   lists the scanners consume — `--ips`
  files, Nostr relay lists, nostr.watch exports — and files derived from them.
- ``OUTPUT_DIR`` (default ``output``): scanner dumps, which `db-import`,
  `db-import-nostr` and the backfill script read back.

Paths are resolved first (``..``, absolute paths, ``~`` and symlinks all
collapse to their real location) and then must sit inside the root.
"""
from __future__ import annotations

import os
from pathlib import Path

INPUT_DIR_ENV = "INPUT_DIR"
DEFAULT_INPUT_DIR = "data"
OUTPUT_DIR_ENV = "OUTPUT_DIR"
DEFAULT_OUTPUT_DIR = "output"

# A ~12k-peer IP list is ~300 KB and a full scanner dump ~10 MB; these caps
# only stop pathological inputs from exhausting memory.
MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_DUMP_BYTES = 500 * 1024 * 1024


class UnsafePathError(ValueError):
    """A CLI path resolves outside its allowed root (or is not a regular file)."""


def _root(env: str, default: str) -> Path:
    return Path(os.getenv(env) or default).expanduser().resolve()


def input_root() -> Path:
    return _root(INPUT_DIR_ENV, DEFAULT_INPUT_DIR)


def output_root() -> Path:
    return _root(OUTPUT_DIR_ENV, DEFAULT_OUTPUT_DIR)


def _within(path: str, root: Path, env: str) -> Path:
    target = Path(path).expanduser().resolve()
    if not target.is_relative_to(root):
        raise UnsafePathError(
            f"{path!r} is outside {root} — move it there or set {env} to its directory"
        )
    return target


def _readable(path: str, root: Path, env: str, max_bytes: int) -> Path:
    target = _within(path, root, env)
    if not target.exists():
        raise FileNotFoundError(f"file not found: {path}")
    if not target.is_file():
        raise UnsafePathError(f"{path!r} is not a regular file")
    if target.stat().st_size > max_bytes:
        raise UnsafePathError(f"{path!r} is larger than {max_bytes} bytes")
    return target


def _writable(path: str, root: Path, env: str) -> Path:
    target = _within(path, root, env)
    if target.exists() and not target.is_file():
        raise UnsafePathError(f"{path!r} exists and is not a regular file")
    return target


def safe_input_file(path: str, max_bytes: int = MAX_INPUT_BYTES) -> Path:
    """An existing regular file under INPUT_DIR."""
    return _readable(path, input_root(), INPUT_DIR_ENV, max_bytes)


def safe_input_write(path: str) -> Path:
    """A file path under INPUT_DIR that may be created or overwritten."""
    return _writable(path, input_root(), INPUT_DIR_ENV)


def safe_output_file(path: str, max_bytes: int = MAX_DUMP_BYTES) -> Path:
    """An existing regular file under OUTPUT_DIR (a scanner dump to import)."""
    return _readable(path, output_root(), OUTPUT_DIR_ENV, max_bytes)


def safe_output_dir(path: str) -> Path:
    """An existing directory under OUTPUT_DIR."""
    target = _within(path, output_root(), OUTPUT_DIR_ENV)
    if not target.is_dir():
        raise UnsafePathError(f"{path!r} is not a directory")
    return target


def safe_output_write(path: str) -> Path:
    """A file path under OUTPUT_DIR that may be created or overwritten."""
    return _writable(path, output_root(), OUTPUT_DIR_ENV)
