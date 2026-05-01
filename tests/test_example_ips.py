"""Tests for the canonical example IP module."""
import pytest

from src.example_ips import EXAMPLE_IPS, is_example_ip


CANONICAL_IPS = ("192.0.2.7", "198.51.100.13", "203.0.113.42", "203.0.113.99")


class TestExampleIPs:
    def test_canonical_set_contains_documented_ips(self):
        # Asserts against the imported module-level constant — do NOT
        # introduce a local `EXAMPLE_IPS` here, that would shadow the
        # import and let the canonical set drift silently.
        for ip in CANONICAL_IPS:
            assert ip in EXAMPLE_IPS, f"{ip} missing from src.example_ips.EXAMPLE_IPS"
        assert len(EXAMPLE_IPS) == len(CANONICAL_IPS)

    def test_canonical_ips_are_in_rfc5737_documentation_ranges(self):
        # Guard against accidentally re-introducing publicly routable IPs
        # (e.g. 1.2.3.4) into the canonical set. RFC 5737 reserves these
        # three /24 blocks exclusively for documentation.
        from ipaddress import ip_address, ip_network

        rfc5737 = (
            ip_network("192.0.2.0/24"),
            ip_network("198.51.100.0/24"),
            ip_network("203.0.113.0/24"),
        )
        for ip in EXAMPLE_IPS:
            addr = ip_address(ip)
            assert any(addr in net for net in rfc5737), (
                f"{ip} is not in any RFC 5737 documentation range"
            )

    @pytest.mark.parametrize("ip", CANONICAL_IPS)
    def test_recognized_ips_return_true(self, ip):
        assert is_example_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        ["8.8.8.8", "1.2.3.4", "5.6.7.8", "9.10.11.12", "1.3.3.7", "192.168.1.1"],
    )
    def test_unknown_or_publicly_routable_ips_return_false(self, ip):
        # Includes the four publicly routable IPs that were briefly canonical
        # earlier in this PR — they MUST now report False.
        assert is_example_ip(ip) is False

    @pytest.mark.parametrize("value", [None, "", "not-an-ip", 0, 123, [], {}, b"192.0.2.7"])
    def test_invalid_input_is_rejected_safely(self, value):
        assert is_example_ip(value) is False
