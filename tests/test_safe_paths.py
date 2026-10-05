"""Tests for src.safe_paths and its use at every CLI file entry point."""
import json
import os

import pytest

from src.safe_paths import (
    UnsafePathError,
    safe_input_file,
    safe_input_write,
    safe_output_dir,
    safe_output_file,
    safe_output_write,
)


@pytest.fixture
def roots(tmp_path, monkeypatch):
    inp, out, outside = tmp_path / "data", tmp_path / "output", tmp_path / "elsewhere"
    for d in (inp, out, outside):
        d.mkdir()
    monkeypatch.setenv("INPUT_DIR", str(inp))
    monkeypatch.setenv("OUTPUT_DIR", str(out))
    return inp, out, outside


class TestSafePaths:
    def test_file_inside_root_is_allowed(self, roots):
        inp, out, _ = roots
        (inp / "peers.txt").write_text("1.1.1.1\n")
        (out / "nodes.json").write_text("[]")
        assert safe_input_file(str(inp / "peers.txt")) == (inp / "peers.txt").resolve()
        assert safe_output_file(str(out / "nodes.json")) == (out / "nodes.json").resolve()

    def test_relative_path_resolves_against_cwd(self, roots, monkeypatch):
        inp, _, _ = roots
        (inp / "peers.txt").write_text("1.1.1.1\n")
        monkeypatch.chdir(inp.parent)
        assert safe_input_file("data/peers.txt").name == "peers.txt"

    @pytest.mark.parametrize("make", [
        lambda inp, outside: str(outside / "secret.txt"),               # absolute, outside
        lambda inp, outside: str(inp / ".." / "elsewhere" / "secret.txt"),  # dot-dot escape
    ])
    def test_escape_is_rejected(self, roots, make):
        inp, _, outside = roots
        (outside / "secret.txt").write_text("10.0.0.1\n")
        with pytest.raises(UnsafePathError, match="INPUT_DIR"):
            safe_input_file(make(inp, outside))

    def test_symlink_pointing_outside_is_rejected(self, roots):
        inp, _, outside = roots
        (outside / "secret.txt").write_text("x")
        (inp / "link.txt").symlink_to(outside / "secret.txt")
        with pytest.raises(UnsafePathError):
            safe_input_file(str(inp / "link.txt"))

    def test_system_file_rejected(self, roots):
        with pytest.raises(UnsafePathError):
            safe_input_file("/etc/hosts")

    def test_directory_and_missing_rejected(self, roots):
        inp, _, _ = roots
        (inp / "sub").mkdir()
        with pytest.raises(UnsafePathError, match="regular file"):
            safe_input_file(str(inp / "sub"))
        with pytest.raises(FileNotFoundError):
            safe_input_file(str(inp / "missing.txt"))

    def test_size_cap(self, roots):
        inp, _, _ = roots
        (inp / "big.txt").write_text("x" * 100)
        with pytest.raises(UnsafePathError, match="larger"):
            safe_input_file(str(inp / "big.txt"), max_bytes=10)

    def test_write_targets(self, roots):
        inp, out, outside = roots
        assert safe_output_write(str(out / "new.json")).name == "new.json"
        assert safe_input_write(str(inp / "relays.txt")).name == "relays.txt"
        with pytest.raises(UnsafePathError):
            safe_output_write(str(outside / "x.json"))
        with pytest.raises(UnsafePathError):
            safe_output_write(os.path.expanduser("~/.bashrc"))

    def test_output_dir(self, roots):
        _, out, outside = roots
        assert safe_output_dir(str(out)) == out.resolve()
        with pytest.raises(UnsafePathError):
            safe_output_dir(str(outside))


class TestEntryPointsRefuseOutsidePaths:
    def test_ip_list(self, roots):
        from src.ip_list import read_ip_list
        _, _, outside = roots
        (outside / "peers.txt").write_text("1.1.1.1\n")
        with pytest.raises(UnsafePathError):
            read_ip_list(str(outside / "peers.txt"))

    def test_nostr_relay_list(self, roots):
        from src.nostr.scanner import read_hosts
        _, _, outside = roots
        (outside / "relays.txt").write_text("wss://relay.example\n")
        with pytest.raises(UnsafePathError):
            read_hosts(str(outside / "relays.txt"))

    def test_nostr_json_output(self, roots, monkeypatch):
        from src.nostr import scanner as nostr_scanner
        inp, _, outside = roots
        (inp / "relays.txt").write_text("wss://relay.example\n")
        monkeypatch.setattr(nostr_scanner, "build_provider_nets", lambda: {})
        with pytest.raises(UnsafePathError):
            nostr_scanner.main([str(inp / "relays.txt"), "--json", str(outside / "dump.json")])
        assert not (outside / "dump.json").exists()

    def test_extract_relays_output(self, roots):
        from src.nostr.extract_relays import extract
        inp, _, outside = roots
        (inp / "export.xlsx").write_bytes(b"not used")
        with pytest.raises(UnsafePathError):
            extract(str(inp / "export.xlsx"), str(outside / "relays.txt"))

    def test_db_import_file(self, roots):
        import importlib.util
        import sys
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "import_json_to_db",
            Path(__file__).resolve().parent.parent / "scripts" / "import_json_to_db.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules.setdefault("import_json_to_db", mod)
        spec.loader.exec_module(mod)
        _, _, outside = roots
        (outside / "nodes.json").write_text(json.dumps([{"ip": "1.1.1.1", "port": 8333}]))
        importer = mod.JSONImporter(verbose=False)
        stats = importer.import_file(str(outside / "nodes.json"))
        assert stats["errors"] == 1 and stats["imported"] == 0
        before = dict(importer.stats)
        importer.import_directory(str(outside))
        assert importer.stats["nodes_imported"] == before["nodes_imported"]

    def test_db_import_nostr(self, roots, capsys):
        import argparse
        from unittest.mock import patch
        from src.db.cli import cmd_import_nostr
        _, _, outside = roots
        (outside / "dump.json").write_text("{}")
        with patch("src.db.cli.is_database_configured", return_value=True), \
             patch("src.db.cli.init_db"):
            assert cmd_import_nostr(argparse.Namespace(file=str(outside / "dump.json"))) == 1
        assert "OUTPUT_DIR" in capsys.readouterr().out
