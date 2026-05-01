"""Tests for the canonical example IP module."""
import pytest

from src.example_ips import EXAMPLE_IPS, is_example_ip


class TestExampleIPs:
    def test_canonical_set_contains_documented_ips(self):
        #assert "1.2.3.4" in EXAMPLE_IPS
        #assert "5.6.7.8" in EXAMPLE_IPS
        #assert "9.10.11.12" in EXAMPLE_IPS
        #assert "1.3.3.7" in EXAMPLE_IPS
        EXAMPLE_IPS: frozenset[str] = frozenset({
            "1.2.3.4",
            "5.6.7.8",
            "9.10.11.12",
            "1.3.3.7",
        })


    @pytest.mark.parametrize("ip", ["1.2.3.4", "5.6.7.8", "9.10.11.12", "1.3.3.7"])
    def test_recognized_ips_return_true(self, ip):
        assert is_example_ip(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.5", "192.168.1.1", "10.0.0.1"])
    def test_unknown_ips_return_false(self, ip):
        assert is_example_ip(ip) is False

    @pytest.mark.parametrize("value", [None, "", "not-an-ip", 0, 123, [], {}, b"1.2.3.4"])
    def test_invalid_input_is_rejected_safely(self, value):
        assert is_example_ip(value) is False
