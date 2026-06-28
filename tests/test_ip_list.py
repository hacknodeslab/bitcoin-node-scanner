"""Unit tests for the --ips list reader (src/ip_list.py)."""
from src.ip_list import parse_ip_line, read_ip_list


class TestParseIpLine:
    def test_ipv4_host_port(self):
        assert parse_ip_line("1.10.205.86:8333") == ("1.10.205.86", 8333)

    def test_bracketed_ipv6_host_port(self):
        assert parse_ip_line("[2001:db8::1]:8333") == ("2001:db8::1", 8333)

    def test_bracketed_ipv6_no_port(self):
        assert parse_ip_line("[2001:db8::1]") == ("2001:db8::1", None)

    def test_non_default_port_preserved(self):
        assert parse_ip_line("1.120.5.214:9333") == ("1.120.5.214", 9333)

    def test_csv_ip_port(self):
        assert parse_ip_line("203.0.113.5,8333") == ("203.0.113.5", 8333)

    def test_csv_ipv6(self):
        assert parse_ip_line("2001:db8::1,8333") == ("2001:db8::1", 8333)

    def test_bare_ipv4(self):
        assert parse_ip_line("203.0.113.5") == ("203.0.113.5", None)

    def test_bare_ipv6_not_split_as_port(self):
        # An unbracketed IPv6 has many colons — must NOT be read as host:port.
        assert parse_ip_line("2001:db8::1") == ("2001:db8::1", None)

    def test_unbracketed_ipv6_with_port(self):
        # peer-observer also emits full IPv6 + :port without brackets.
        assert parse_ip_line("2001:0:14c9:cd04:2056:dc3a:629b:79f6:8333") == (
            "2001:0:14c9:cd04:2056:dc3a:629b:79f6", 8333)

    def test_port_zero_means_unknown_keeps_ip(self):
        # :0 = unknown port → keep the IP, no port (still looked up via defaults).
        assert parse_ip_line("172.33.0.11:0") == ("172.33.0.11", None)

    def test_blank_and_comment(self):
        assert parse_ip_line("") is None
        assert parse_ip_line("   ") is None
        assert parse_ip_line("# a comment") is None

    def test_invalid_ip(self):
        assert parse_ip_line("not.an.ip:8333") is None
        assert parse_ip_line("999.999.999.999") is None

    def test_invalid_port(self):
        assert parse_ip_line("1.2.3.4:70000") is None
        assert parse_ip_line("1.2.3.4:abc") is None

    def test_csv_too_many_fields_rejected(self):
        # A malformed CSV row must be rejected, not silently truncated.
        assert parse_ip_line("1.2.3.4,8333,extra") is None


class TestReadIpList:
    def test_mixed_file(self, tmp_path):
        p = tmp_path / "peers.txt"
        p.write_text(
            "# header comment\n"
            "1.10.205.86:8333\n"
            "[2001:db8::1]:8333\n"
            "1.120.5.214:9333\n"
            "203.0.113.5,8332\n"
            "198.51.100.7\n"
            "\n"
            "garbage-line\n"
        )
        entries, counts = read_ip_list(str(p))
        as_dict = dict(entries)
        assert as_dict["1.10.205.86"] == [8333]
        assert as_dict["2001:db8::1"] == [8333]
        assert as_dict["1.120.5.214"] == [9333]
        assert as_dict["203.0.113.5"] == [8332]
        assert as_dict["198.51.100.7"] == []
        assert counts["unique"] == 5
        assert counts["invalid"] == 1  # "garbage-line"
        assert counts["raw"] == 6      # non-blank, non-comment lines

    def test_duplicate_ips_merge_ports(self, tmp_path):
        p = tmp_path / "dup.txt"
        p.write_text("1.2.3.4:8333\n1.2.3.4:8332\n1.2.3.4\n")
        entries, counts = read_ip_list(str(p))
        assert counts["unique"] == 1
        assert dict(entries)["1.2.3.4"] == [8332, 8333]

    def test_preserves_first_seen_order(self, tmp_path):
        p = tmp_path / "order.txt"
        p.write_text("9.9.9.9\n1.1.1.1\n5.5.5.5\n")
        entries, _ = read_ip_list(str(p))
        assert [ip for ip, _ in entries] == ["9.9.9.9", "1.1.1.1", "5.5.5.5"]
