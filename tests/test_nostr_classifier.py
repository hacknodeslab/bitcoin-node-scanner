"""Unit tests for the Nostr CDN-recon classifier and scanner aggregation."""
import ipaddress
from unittest.mock import patch

import pytest

from src.nostr.classifier import classify, normalize, provider_for
from src.nostr import scanner


# A tiny fixture net map: one Cloudflare range, one Fastly range.
NETS = {
    "cloudflare": [ipaddress.ip_network("104.16.0.0/13")],
    "cloudfront": [ipaddress.ip_network("13.32.0.0/15")],
    "fastly": [ipaddress.ip_network("151.101.0.0/16")],
}


class TestNormalize:
    def test_strips_wss_scheme_and_path(self):
        assert normalize("wss://relay.example.com/") == "relay.example.com"

    def test_bare_host_passes_through(self):
        assert normalize("relay.example.com") == "relay.example.com"

    def test_lowercases(self):
        assert normalize("wss://Relay.Example.COM") == "relay.example.com"

    def test_blank_and_comment_lines_ignored(self):
        assert normalize("") is None
        assert normalize("   ") is None
        assert normalize("# a comment") is None

    def test_dedup_is_callers_job_but_normalize_is_stable(self):
        # Two URL forms of the same host normalize identically.
        assert normalize("wss://relay.x/") == normalize("relay.x")


class TestProviderFor:
    def test_cloudflare_ip_matches(self):
        assert provider_for("104.16.0.1", NETS) == "cloudflare"

    def test_fastly_ip_matches(self):
        assert provider_for("151.101.1.1", NETS) == "fastly"

    def test_unmatched_ip_returns_none(self):
        assert provider_for("8.8.8.8", NETS) is None


class TestClassify:
    def test_onion_is_skipped_without_dns(self):
        with patch("src.nostr.classifier.resolve") as mock_resolve:
            r = classify("abcd.onion", NETS)
        assert r["verdict"] == "skipped"
        assert r["error"] == "onion/i2p"
        mock_resolve.assert_not_called()

    def test_i2p_is_skipped(self):
        r = classify("abcd.i2p", NETS)
        assert r["verdict"] == "skipped"

    def test_cloudflare_verdict(self):
        with patch("src.nostr.classifier.resolve", return_value=["104.16.0.5"]):
            r = classify("relay.cf", NETS)
        assert r["verdict"] == "cloudflare"
        assert r["providers"] == ["cloudflare"]

    def test_direct_when_no_range_matches(self):
        with patch("src.nostr.classifier.resolve", return_value=["8.8.8.8"]):
            r = classify("relay.direct", NETS)
        assert r["verdict"] == "direct"
        assert r["providers"] == []

    def test_multi_cdn_verdict_is_plus_joined_sorted(self):
        with patch("src.nostr.classifier.resolve", return_value=["104.16.0.5", "151.101.1.1"]):
            r = classify("relay.multi", NETS)
        assert r["verdict"] == "cloudflare+fastly"
        assert r["providers"] == ["cloudflare", "fastly"]

    def test_dns_error_records_reason(self):
        import socket

        with patch("src.nostr.classifier.resolve", side_effect=socket.gaierror("boom")):
            r = classify("relay.bad", NETS)
        assert r["verdict"] == "dns_error"
        assert r["ips"] == []
        assert r["error"]


class TestSummarize:
    def test_aggregate_counts_consistent(self):
        results = [
            {"host": "a", "verdict": "cloudflare", "ips": ["104.16.0.1"], "providers": ["cloudflare"], "error": None},
            {"host": "b", "verdict": "direct", "ips": ["8.8.8.8"], "providers": [], "error": None},
            {"host": "c", "verdict": "dns_error", "ips": [], "providers": [], "error": "x"},
            {"host": "d", "verdict": "skipped", "ips": [], "providers": [], "error": "onion/i2p"},
            {"host": "e", "verdict": "cloudflare+fastly", "ips": [], "providers": ["cloudflare", "fastly"], "error": None},
        ]
        dump = scanner.summarize(results)
        assert dump["total"] == 5
        # resolved = total - skipped - dns_error
        assert dump["resolved"] == 3
        # behind_any_cdn = cloudflare + cloudflare+fastly = 2
        assert dump["behind_any_cdn"] == 2
        assert dump["counts"]["cloudflare"] == 1
        assert dump["counts"]["direct"] == 1

    def test_empty_results(self):
        dump = scanner.summarize([])
        assert dump == {"counts": {}, "total": 0, "resolved": 0, "behind_any_cdn": 0, "results": []}


class TestReadHosts:
    def test_reads_and_dedupes(self, tmp_path):
        p = tmp_path / "relays.txt"
        p.write_text("wss://relay.x/\n# comment\nrelay.x\nrelay.y\n\n")
        hosts = scanner.read_hosts(str(p))
        assert hosts == ["relay.x", "relay.y"]
