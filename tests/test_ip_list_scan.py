"""Tests for the scanner's --ips host-lookup flow (Shodan mocked)."""
from unittest.mock import MagicMock

import pytest
import shodan

from src.scanner import BitcoinNodeScanner, Config


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    """A scanner with output dirs in tmp and the Shodan client mocked out."""
    for attr, sub in [
        ("OUTPUT_DIR", ""), ("RAW_DATA_DIR", "raw"),
        ("REPORTS_DIR", "reports"), ("LOGS_DIR", "logs"),
    ]:
        monkeypatch.setattr(Config, attr, str(tmp_path / sub))
    s = BitcoinNodeScanner(api_key="test-key")
    s.api = MagicMock()
    return s


def _bitcoin_banner(ip, port, version="25.0"):
    return {
        "ip_str": ip, "port": port, "transport": "tcp",
        "product": "Bitcoin", "version": version,
        "data": f"/Satoshi:{version}/",
        "location": {"country_name": "United States", "country_code": "US", "city": "NY"},
    }


# IP → Shodan host-lookup response (or sentinel for not-found).
HOSTS = {
    # found: a Bitcoin service on 8333; banner omits asn → host-root fallback
    "1.1.1.1": {"data": [_bitcoin_banner("1.1.1.1", 8333)], "asn": "AS1", "org": "OrgA"},
    # found via caller-supplied non-default port 9333
    "4.4.4.4": {"data": [_bitcoin_banner("4.4.4.4", 9333, "24.0")]},
    # found: Bitcoin 8333 + unrelated 22 → only 8333 kept
    "5.5.5.5": {"data": [_bitcoin_banner("5.5.5.5", 8333), {"ip_str": "5.5.5.5", "port": 22, "product": "OpenSSH"}]},
    # in Shodan but no Bitcoin-relevant service
    "3.3.3.3": {"data": [{"ip_str": "3.3.3.3", "port": 80, "product": "nginx"}]},
}


def _host_side_effect(ip):
    if ip == "2.2.2.2":
        raise shodan.APIError("No information available for that IP.")
    return HOSTS[ip]


def _write(tmp_path, lines):
    p = tmp_path / "peers.txt"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


class TestScanFromIpList:
    def test_counts_and_records(self, scanner, tmp_path):
        scanner.api.host.side_effect = _host_side_effect
        path = _write(tmp_path, [
            "1.1.1.1:8333", "2.2.2.2:8333", "3.3.3.3:8333",
            "4.4.4.4:9333", "5.5.5.5:8333",
        ])
        summary = scanner.scan_from_ip_list(path, rate=0)

        assert summary["lookups"] == 5
        assert summary["found"] == 3        # 1.1.1.1, 4.4.4.4, 5.5.5.5
        assert summary["not_found"] == 1    # 2.2.2.2
        assert summary["no_service"] == 1   # 3.3.3.3
        assert len(scanner.results) == 3    # one Bitcoin record each

    def test_non_bitcoin_ports_excluded(self, scanner, tmp_path):
        scanner.api.host.side_effect = _host_side_effect
        path = _write(tmp_path, ["5.5.5.5:8333"])
        scanner.scan_from_ip_list(path, rate=0)
        ports = [n["port"] for n in scanner.results]
        assert ports == [8333]              # the :22 OpenSSH banner is dropped

    def test_caller_supplied_port_honored(self, scanner, tmp_path):
        scanner.api.host.side_effect = _host_side_effect
        path = _write(tmp_path, ["4.4.4.4:9333"])  # 9333 not in default set
        scanner.scan_from_ip_list(path, rate=0)
        assert [n["port"] for n in scanner.results] == [9333]

    def test_host_root_field_fallback(self, scanner, tmp_path):
        scanner.api.host.side_effect = _host_side_effect
        path = _write(tmp_path, ["1.1.1.1:8333"])
        scanner.scan_from_ip_list(path, rate=0)
        assert scanner.results[0]["asn"] == "AS1"   # filled from host root

    def test_not_found_skipped_and_no_scan_called(self, scanner, tmp_path):
        scanner.api.host.side_effect = _host_side_effect
        path = _write(tmp_path, ["2.2.2.2:8333"])
        summary = scanner.scan_from_ip_list(path, rate=0)
        assert summary["not_found"] == 1
        assert scanner.results == []
        scanner.api.scan.assert_not_called()    # never on-demand scans

    def test_max_ips_cap_stops_run(self, scanner, tmp_path):
        scanner.api.host.side_effect = _host_side_effect
        path = _write(tmp_path, ["1.1.1.1:8333", "4.4.4.4:9333", "5.5.5.5:8333"])
        summary = scanner.scan_from_ip_list(path, max_ips=2, rate=0)
        assert summary["lookups"] == 2
        assert scanner.api.host.call_count == 2
