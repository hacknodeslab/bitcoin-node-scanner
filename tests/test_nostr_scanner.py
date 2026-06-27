"""Unit tests for the Nostr scanner internals: CDN ranges, scan orchestration,
and the nostr.watch xlsx extractor. All network and openpyxl access is mocked."""
import json
import os
import sys
import time
import types
from unittest.mock import patch

import pytest

from src.nostr import cdn_ranges, scanner, extract_relays


# ---------------------------------------------------------------------------
# cdn_ranges
# ---------------------------------------------------------------------------

class TestValidators:
    def test_nonempty_lines(self):
        assert cdn_ranges._nonempty_lines("1.2.3.0/24\n")
        assert not cdn_ranges._nonempty_lines("")
        assert not cdn_ranges._nonempty_lines("\n  \n")

    def test_is_json_obj(self):
        assert cdn_ranges._is_json_obj('{"a": 1}')
        assert not cdn_ranges._is_json_obj("[]")
        assert not cdn_ranges._is_json_obj("not json")


class TestFreshAndFetch:
    def test_fresh(self, tmp_path):
        p = tmp_path / "c.txt"
        assert not cdn_ranges._fresh(str(p))  # missing
        p.write_text("x")
        assert cdn_ranges._fresh(str(p))      # just written
        old = time.time() - (cdn_ranges.CACHE_TTL_DAYS + 1) * 86400
        os.utime(p, (old, old))
        assert not cdn_ranges._fresh(str(p))  # stale

    def test_fetch_returns_fresh_valid_cache_without_network(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cdn_ranges, "CACHE_DIR", str(tmp_path))
        (tmp_path / "cf.txt").write_text("1.2.3.0/24\n")
        # urlopen must NOT be called for a fresh, valid cache.
        with patch("urllib.request.urlopen", side_effect=AssertionError("network hit")):
            out = cdn_ranges._fetch("http://x", "cf.txt", cdn_ranges._nonempty_lines)
        assert "1.2.3.0/24" in out

    def test_fetch_refetches_when_cache_invalid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cdn_ranges, "CACHE_DIR", str(tmp_path))
        (tmp_path / "cf.txt").write_text("")  # fresh but empty → invalid

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"9.9.9.0/24\n"

        with patch("urllib.request.urlopen", return_value=_Resp()):
            out = cdn_ranges._fetch("http://x", "cf.txt", cdn_ranges._nonempty_lines)
        assert "9.9.9.0/24" in out
        # written atomically to the real cache path
        assert (tmp_path / "cf.txt").read_text().strip() == "9.9.9.0/24"


class TestLoaders:
    def test_cloudflare_success(self):
        with patch.object(cdn_ranges, "_fetch", side_effect=["1.2.3.0/24\n", "2606:4700::/32\n"]):
            out = cdn_ranges.load_cloudflare()
        assert out == ["1.2.3.0/24", "2606:4700::/32"]

    def test_cloudflare_empty_falls_back(self):
        with patch.object(cdn_ranges, "_fetch", return_value=""):
            out = cdn_ranges.load_cloudflare()
        assert out is cdn_ranges.CLOUDFLARE_FALLBACK

    def test_cloudflare_exception_falls_back(self):
        with patch.object(cdn_ranges, "_fetch", side_effect=OSError("boom")):
            out = cdn_ranges.load_cloudflare()
        assert out is cdn_ranges.CLOUDFLARE_FALLBACK

    def test_cloudfront_filters_service(self):
        payload = json.dumps({
            "prefixes": [
                {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
                {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
            ],
            "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"}],
        })
        with patch.object(cdn_ranges, "_fetch", return_value=payload):
            out = cdn_ranges.load_cloudfront()
        assert out == ["13.32.0.0/15", "2600:9000::/28"]

    def test_fastly_merges_v4_v6(self):
        payload = json.dumps({"addresses": ["151.101.0.0/16"], "ipv6_addresses": ["2a04:4e40::/32"]})
        with patch.object(cdn_ranges, "_fetch", return_value=payload):
            out = cdn_ranges.load_fastly()
        assert out == ["151.101.0.0/16", "2a04:4e40::/32"]


class TestBuildProviderNets:
    def test_skips_malformed_cidr(self, monkeypatch):
        monkeypatch.setitem(cdn_ranges._LOADERS, "cloudflare", lambda: ["104.16.0.0/13", "not-a-cidr"])
        monkeypatch.setitem(cdn_ranges._LOADERS, "cloudfront", lambda: [])
        monkeypatch.setitem(cdn_ranges._LOADERS, "fastly", lambda: [])
        nets = cdn_ranges.build_provider_nets()
        assert len(nets["cloudflare"]) == 1  # malformed entry skipped, valid kept

    def test_loader_exception_degrades_to_empty(self, monkeypatch):
        def _boom():
            raise RuntimeError("feed down")
        monkeypatch.setitem(cdn_ranges._LOADERS, "cloudflare", _boom)
        monkeypatch.setitem(cdn_ranges._LOADERS, "cloudfront", lambda: [])
        monkeypatch.setitem(cdn_ranges._LOADERS, "fastly", lambda: [])
        nets = cdn_ranges.build_provider_nets()
        assert nets["cloudflare"] == []


# ---------------------------------------------------------------------------
# scanner
# ---------------------------------------------------------------------------

class TestScanHosts:
    def test_classifies_all_hosts(self):
        def fake_classify(host, nets):
            return {"host": host, "verdict": "direct", "ips": [], "providers": [], "error": None}
        with patch("src.nostr.scanner.classify", side_effect=fake_classify):
            results = scanner.scan_hosts(["a", "b", "c"], {}, workers=3, timeout=1.0)
        assert {r["host"] for r in results} == {"a", "b", "c"}

    def test_timeout_records_dns_error(self):
        def slow_classify(host, nets):
            time.sleep(0.5)
            return {"host": host, "verdict": "direct", "ips": [], "providers": [], "error": None}
        with patch("src.nostr.scanner.classify", side_effect=slow_classify):
            results = scanner.scan_hosts(["slow"], {}, workers=1, timeout=0.01)
        assert results[0]["verdict"] == "dns_error"
        assert results[0]["error"] == "timeout"


class TestScannerMain:
    def test_main_writes_dump(self, tmp_path):
        inp = tmp_path / "relays.txt"
        inp.write_text("wss://a.relay\nwss://b.relay\n")
        out = tmp_path / "dump.json"

        def fake_classify(host, nets):
            return {"host": host, "verdict": "direct", "ips": ["8.8.8.8"], "providers": [], "error": None}

        with patch("src.nostr.scanner.build_provider_nets", return_value={"cloudflare": []}), \
             patch("src.nostr.scanner.classify", side_effect=fake_classify):
            rc = scanner.main([str(inp), "--json", str(out), "--workers", "2", "--timeout", "1"])
        assert rc == 0
        dump = json.loads(out.read_text())
        assert dump["total"] == 2
        assert dump["resolved"] == 2

    def test_default_output_path_uses_output_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
        p = scanner._default_output_path()
        assert p.startswith(str(tmp_path))
        assert p.endswith(".json")


# ---------------------------------------------------------------------------
# extract_relays (openpyxl mocked)
# ---------------------------------------------------------------------------

def _fake_openpyxl(rows):
    """Return a fake `openpyxl` module whose load_workbook yields `rows`."""
    class _WS:
        def iter_rows(self, values_only=False):
            return iter(rows)

    class _WB:
        active = _WS()

    mod = types.ModuleType("openpyxl")
    mod.load_workbook = lambda src, read_only=True: _WB()
    return mod


class TestExtractRelays:
    def test_no_flags_dedupes(self, tmp_path):
        rows = [
            ("url", "in_rstate", "network"),
            ("wss://a", True, "clearnet"),
            ("wss://b", False, "tor"),
            ("wss://a", True, "clearnet"),  # dup
            ("", True, "clearnet"),          # empty url skipped
        ]
        dst = tmp_path / "out.txt"
        with patch.dict(sys.modules, {"openpyxl": _fake_openpyxl(rows)}):
            count = extract_relays.extract("x.xlsx", str(dst))
        assert count == 2
        assert dst.read_text().split() == ["wss://a", "wss://b"]

    def test_online_filter(self, tmp_path):
        rows = [
            ("url", "in_rstate", "network"),
            ("wss://a", True, "clearnet"),
            ("wss://b", False, "tor"),
        ]
        dst = tmp_path / "out.txt"
        with patch.dict(sys.modules, {"openpyxl": _fake_openpyxl(rows)}):
            count = extract_relays.extract("x.xlsx", str(dst), only_online=True)
        assert count == 1
        assert dst.read_text().strip() == "wss://a"

    def test_clearnet_filter(self, tmp_path):
        rows = [
            ("url", "in_rstate", "network"),
            ("wss://a", True, "clearnet"),
            ("wss://b", True, "tor"),
        ]
        dst = tmp_path / "out.txt"
        with patch.dict(sys.modules, {"openpyxl": _fake_openpyxl(rows)}):
            count = extract_relays.extract("x.xlsx", str(dst), only_clearnet=True)
        assert count == 1
        assert dst.read_text().strip() == "wss://a"

    def test_no_flags_tolerates_missing_optional_columns(self, tmp_path):
        # A sheet with only a `url` column must not crash when no flag is set.
        rows = [("url",), ("wss://x",)]
        dst = tmp_path / "out.txt"
        with patch.dict(sys.modules, {"openpyxl": _fake_openpyxl(rows)}):
            count = extract_relays.extract("x.xlsx", str(dst))
        assert count == 1

    def test_main_usage_error(self, capsys):
        rc = extract_relays.main(["only-one-arg"])
        assert rc == 1
