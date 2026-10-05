"""Tests for src.peers (alt-bitnodes peer source). All HTTP is mocked.

conftest points INPUT_DIR at tmp_path, so default cache/output live there.
"""
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock

import pytest
import requests

from src.ip_list import read_ip_list
from src.peers import alt_bitnodes as ab
from src.peers import fetch
from src.safe_paths import UnsafePathError

NOW = 1_791_200_000.0
DAY = 86400


def _resp(status: int = 200, payload=None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    return r


class FakeApi:
    """Serves a snapshot listing (newest first, paginated) and snapshot bodies."""

    def __init__(self, snapshots: Dict[int, List[str]], fail: Optional[Dict[str, int]] = None,
                 list_status: int = 200):
        self.snapshots = snapshots
        self.fail = fail or {}
        self.list_status = list_status
        self.calls: List[str] = []

    def get(self, url, params=None, timeout=None, headers=None):
        assert headers["User-Agent"] == ab.USER_AGENT
        path = url.split("pesquisa.hacknodes.xyz", 1)[1] if "pesquisa" in url else url
        self.calls.append(path if not params else f"{path}?page={params['page']}")
        if path == "/api/v1/snapshots/":
            if self.list_status != 200:
                return _resp(self.list_status)
            ordered = sorted(self.snapshots, reverse=True)
            page, limit = params["page"], params["limit"]
            chunk = ordered[(page - 1) * limit: page * limit]
            has_next = page * limit < len(ordered)
            return _resp(200, {
                "count": len(ordered),
                "next": f"/api/v1/snapshots/?page={page + 1}" if has_next else None,
                "results": [{"url": f"/api/v1/snapshots/{ts}/", "timestamp": ts} for ts in chunk],
            })
        ts = int(path.strip("/").split("/")[-1])
        if path in self.fail:
            return _resp(self.fail[path])
        return _resp(200, {"timestamp": ts, "nodes": {k: [70016] for k in self.snapshots[ts]}})

    def downloads(self) -> List[str]:
        return [c for c in self.calls if not c.startswith("/api/v1/snapshots/?")]


def _client(api: FakeApi) -> ab.AltBitnodesClient:
    return ab.AltBitnodesClient(http=api, sleep=lambda s: None)


# ---------------------------------------------------------------------------
# 3.1 parsing
# ---------------------------------------------------------------------------

class TestParsing:
    def test_ipv4(self):
        assert ab.parse_node_key("104.12.253.50:8333") == ("104.12.253.50", 8333)

    def test_unbracketed_compressed_ipv6_keeps_port(self):
        parsed = ab.parse_node_key("2a07:9a07:3::2:105:8333")
        assert parsed == ("2a07:9a07:3::2:105", 8333)
        assert ab.format_entry(*parsed) == "[2a07:9a07:3::2:105]:8333"

    def test_non_default_port(self):
        assert ab.format_entry(*ab.parse_node_key("5.6.7.8:9333")) == "5.6.7.8:9333"

    def test_ipv6_is_normalised(self):
        # Full (uncompressed) form: the last group is still the port.
        assert ab.parse_node_key("2a07:9a07:0003:0000:0000:0002:0105:0000:8333") == (
            "2a07:9a07:3::2:105:0", 8333)
        # Already-bracketed keys are accepted too.
        assert ab.parse_node_key("[2a07:9a07:0003::0002:0105]:8333") == ("2a07:9a07:3::2:105", 8333)

    @pytest.mark.parametrize("key,reason", [
        ("abcdefghijklmnop.onion:8333", "onion"),
        ("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p:0", "i2p"),
        ("fc32:17ea:e415:c3bf:9808:149d:b5a2:c9aa:8333", "cjdns"),
        ("10.0.0.5:8333", "non_global"),
        ("127.0.0.1:8333", "non_global"),
        ("192.0.2.7:8333", "non_global"),  # RFC 5737 documentation range
        ("not-an-ip:8333", "invalid"),
        ("1.2.3.4:0", "invalid"),
        ("1.2.3.4:70000", "invalid"),
        ("1.2.3.4", "invalid"),
        (None, "invalid"),
    ])
    def test_skipped_with_reason(self, key, reason):
        assert ab.classify_key(key) == (None, reason)


# ---------------------------------------------------------------------------
# union, window, pagination
# ---------------------------------------------------------------------------

def _snaps(*spec) -> Dict[int, List[str]]:
    return {int(NOW - age_days * DAY): keys for age_days, keys in spec}


class TestBuildUnion:
    def test_union_across_snapshots_and_ipv6_round_trip(self, tmp_path):
        api = FakeApi(_snaps(
            (2, ["1.1.1.1:8333", "2a07:9a07:3::2:105:8333"]),
            (1, ["1.1.1.1:8333", "2.2.2.2:9333", "abc.onion:8333"]),
        ))
        s = ab.build_union(days=8, client=_client(api), now=NOW)
        lines = [ln for ln in Path(s["output"]).read_text().splitlines() if not ln.startswith("#")]
        assert lines == ["1.1.1.1:8333", "2.2.2.2:9333", "[2a07:9a07:3::2:105]:8333"]
        assert s["unique_ipv4"] == 2 and s["unique_ipv6"] == 1
        assert s["skipped"] == {"onion": 1}
        # 3.6 round trip through the --ips reader
        entries, counts = read_ip_list(s["output"])
        assert dict(entries) == {"1.1.1.1": [8333], "2.2.2.2": [9333], "2a07:9a07:3::2:105": [8333]}
        assert counts["invalid"] == 0

    def test_out_of_window_snapshots_not_downloaded(self, tmp_path):
        snaps = _snaps((1, ["1.1.1.1:8333"]), (9, ["9.9.9.9:8333"]))
        api = FakeApi(snaps)
        s = ab.build_union(days=8, client=_client(api), now=NOW)
        assert len(api.downloads()) == 1
        assert "9.9.9.9:8333" not in Path(s["output"]).read_text()

    def test_pagination_stops_past_window(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ab, "PAGE_LIMIT", 2)
        # 3 in-window snapshots then many older ones: should read 2 pages only.
        spec = [(d, [f"1.1.1.{i}:8333"]) for i, d in enumerate([1, 2, 3], start=1)]
        spec += [(10 + i, ["9.9.9.9:8333"]) for i in range(10)]
        api = FakeApi(_snaps(*spec))
        ab.build_union(days=8, client=_client(api), now=NOW)
        pages = [c for c in api.calls if c.startswith("/api/v1/snapshots/?")]
        assert pages == ["/api/v1/snapshots/?page=1", "/api/v1/snapshots/?page=2"]

    def test_header_comments(self, tmp_path):
        api = FakeApi(_snaps((1, ["1.1.1.1:8333"])))
        s = ab.build_union(days=8, client=_client(api), now=NOW)
        header = [ln for ln in Path(s["output"]).read_text().splitlines() if ln.startswith("#")]
        assert any("source: alt-bitnodes" in h for h in header)
        assert any("window: last 8 days" in h for h in header)
        assert any("--source-tag alt-bitnodes" in h for h in header)


# ---------------------------------------------------------------------------
# 3.3 cache
# ---------------------------------------------------------------------------

class TestCache:
    def test_daily_run_downloads_only_new_snapshots(self, tmp_path):
        snaps = _snaps(*[(d, [f"1.1.1.{d}:8333"]) for d in (5, 4, 3, 2)])
        ab.build_union(days=8, client=_client(FakeApi(snaps)), now=NOW)
        snaps.update(_snaps((1, ["2.2.2.2:8333"]), (0.5, ["3.3.3.3:8333"])))
        api = FakeApi(snaps)
        s = ab.build_union(days=8, client=_client(api), now=NOW)
        assert len(api.downloads()) == 2
        assert s["from_cache"] == 4 and s["downloaded"] == 2

    def test_empty_or_foreign_cache_file_is_refetched(self, tmp_path):
        snaps = _snaps((1, ["1.1.1.1:8333"]))
        ts = next(iter(snaps))
        ab.cache_dir().mkdir(parents=True)
        (ab.cache_dir() / f"{ts}.txt").write_text("")
        api = FakeApi(snaps)
        ab.build_union(days=8, client=_client(api), now=NOW)
        assert len(api.downloads()) == 1
        assert ab.read_cache(ab.cache_dir() / f"{ts}.txt") == ["1.1.1.1:8333"]

    def test_snapshot_with_no_usable_keys_is_cached_not_refetched(self, tmp_path):
        snaps = _snaps((1, ["abc.onion:8333"]), (2, ["1.1.1.1:8333"]))
        ab.build_union(days=8, client=_client(FakeApi(snaps)), now=NOW)
        api = FakeApi(snaps)
        ab.build_union(days=8, client=_client(api), now=NOW)
        assert api.downloads() == []

    def test_old_cache_files_pruned(self, tmp_path):
        ab.cache_dir().mkdir(parents=True)
        old = ab.cache_dir() / f"{int(NOW - 20 * DAY)}.txt"
        old.write_text("# alt-bitnodes snapshot x\n9.9.9.9:8333\n")
        s = ab.build_union(days=8, client=_client(FakeApi(_snaps((1, ["1.1.1.1:8333"])))), now=NOW)
        assert not old.exists() and s["pruned"] == 1
        assert "9.9.9.9" not in Path(s["output"]).read_text()


# ---------------------------------------------------------------------------
# 3.4 failures
# ---------------------------------------------------------------------------

class TestFailures:
    def test_one_snapshot_failing_is_skipped(self, tmp_path):
        snaps = _snaps(*[(d, [f"1.1.1.{d}:8333"]) for d in range(1, 11)])
        bad_ts = int(NOW - 3 * DAY)
        api = FakeApi(snaps, fail={f"/api/v1/snapshots/{bad_ts}/": 500})
        s = ab.build_union(days=11, client=_client(api), now=NOW)
        assert s["failed"] == 1 and s["downloaded"] == 9
        assert "1.1.1.3:8333" not in Path(s["output"]).read_text()
        # three attempts were made for the failing snapshot
        assert api.downloads().count(f"/api/v1/snapshots/{bad_ts}/") == 3

    def test_retry_on_503_then_success(self, tmp_path):
        http = MagicMock()
        http.get.side_effect = [_resp(503), _resp(200, {"results": [], "next": None})]
        assert ab.AltBitnodesClient(http=http, sleep=lambda s: None).list_snapshots(0) == []
        assert http.get.call_count == 2

    def test_network_error_retried(self, tmp_path):
        http = MagicMock()
        http.get.side_effect = requests.ConnectionError("down")
        with pytest.raises(ab.FetchError):
            ab.AltBitnodesClient(http=http, sleep=lambda s: None).list_snapshots(0)
        assert http.get.call_count == 3

    def test_403_is_not_retried_and_explains(self, tmp_path):
        http = MagicMock()
        http.get.return_value = _resp(403)
        with pytest.raises(ab.FetchError, match="403"):
            ab.AltBitnodesClient(http=http, sleep=lambda s: None).list_snapshots(0)
        assert http.get.call_count == 1

    def test_listing_failure_leaves_previous_output(self, tmp_path):
        out = ab.default_output()
        out.parent.mkdir(parents=True)
        out.write_text("previous\n")
        api = FakeApi(_snaps((1, ["1.1.1.1:8333"])), list_status=500)
        with pytest.raises(ab.FetchError):
            ab.build_union(days=8, client=_client(api), now=NOW)
        assert out.read_text() == "previous\n"

    def test_empty_window_is_an_error(self, tmp_path):
        api = FakeApi(_snaps((30, ["1.1.1.1:8333"])))
        with pytest.raises(ab.FetchError, match="no alt-bitnodes snapshot"):
            ab.build_union(days=8, client=_client(api), now=NOW)


# ---------------------------------------------------------------------------
# 3.5 paths + CLI
# ---------------------------------------------------------------------------

class TestPathsAndCli:
    def test_output_outside_input_dir_refused_before_any_request(self, tmp_path):
        api = FakeApi(_snaps((1, ["1.1.1.1:8333"])))
        with pytest.raises(UnsafePathError):
            ab.build_union(days=8, output="/tmp/peers.txt", client=_client(api), now=NOW)
        assert api.calls == []

    def test_cli_success_prints_summary_and_next_command(self, tmp_path, monkeypatch, capsys):
        api = FakeApi(_snaps((1, ["1.1.1.1:8333", "2a07:9a07:3::2:105:8333"])))
        real_client = ab.AltBitnodesClient
        monkeypatch.setattr(ab, "AltBitnodesClient",
                            lambda **kw: real_client(http=api, sleep=lambda s: None))
        assert fetch.main(["alt-bitnodes", "--days", "8"]) == 0
        out = capsys.readouterr().out
        assert "IPv4 1, IPv6 1" in out
        assert "--source-tag alt-bitnodes" in out

    def test_cli_refused_output_exits_1(self, tmp_path, capsys):
        assert fetch.main(["alt-bitnodes", "--output", "/etc/peers.txt"]) == 1
        assert "INPUT_DIR" in capsys.readouterr().out

    def test_cli_rejects_zero_days(self, tmp_path, capsys):
        assert fetch.main(["alt-bitnodes", "--days", "0"]) == 1

