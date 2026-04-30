"""
Unit tests for NVDClient — mocked HTTP responses.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.nvd.client import NVDClient
from src.nvd.models import NVDAPIError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nvd_response(total: int, items: list) -> dict:
    return {
        "totalResults": total,
        "resultsPerPage": len(items),
        "startIndex": 0,
        "vulnerabilities": items,
    }


def _cve_item(
    cve_id: str,
    score: float = 7.5,
    severity: str = "HIGH",
    cpe_matches: list | None = None,
) -> dict:
    matches = cpe_matches if cpe_matches is not None else [
        {"criteria": "cpe:2.3:a:bitcoin:bitcoin:0.21.0:*:*:*:*:*:*:*"}
    ]
    return {
        "cve": {
            "id": cve_id,
            "published": "2023-01-15T12:00:00.000",
            "lastModified": "2023-06-01T08:30:00.000",
            "descriptions": [{"lang": "en", "value": f"Test vulnerability {cve_id}"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                    }
                }]
            },
            "configurations": [{"nodes": [{"cpeMatch": matches}]}],
        }
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNVDClientFetch:
    def test_single_page_success(self):
        page = _nvd_response(2, [_cve_item("CVE-2023-0001"), _cve_item("CVE-2023-0002")])

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = page

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            client = NVDClient()
            entries = client.fetch_bitcoin_cves()

        assert len(entries) == 2
        assert entries[0].cve_id == "CVE-2023-0001"
        assert entries[1].cve_id == "CVE-2023-0002"

    def test_paginated_fetch(self):
        """Client should iterate all pages and combine results."""
        page1 = {
            "totalResults": 3,
            "resultsPerPage": 2,
            "startIndex": 0,
            "vulnerabilities": [_cve_item("CVE-2023-0001"), _cve_item("CVE-2023-0002")],
        }
        page2 = {
            "totalResults": 3,
            "resultsPerPage": 1,
            "startIndex": 2,
            "vulnerabilities": [_cve_item("CVE-2023-0003")],
        }

        responses = [MagicMock(status_code=200), MagicMock(status_code=200)]
        responses[0].json.return_value = page1
        responses[1].json.return_value = page2

        with patch("src.nvd.client.requests.get", side_effect=responses), \
             patch("src.nvd.client.time.sleep"):
            client = NVDClient()
            entries = client.fetch_bitcoin_cves()

        assert len(entries) == 3
        ids = [e.cve_id for e in entries]
        assert "CVE-2023-0003" in ids

    def test_api_key_included_in_header(self):
        page = _nvd_response(1, [_cve_item("CVE-2023-0001")])
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = page

        with patch("src.nvd.client.requests.get", return_value=mock_resp) as mock_get, \
             patch.dict("os.environ", {"NVD_API_KEY": "test-key-123"}):
            client = NVDClient()
            client.fetch_bitcoin_cves()

        call_kwargs = mock_get.call_args
        headers = call_kwargs[1].get("headers", {})
        assert headers.get("apiKey") == "test-key-123"

    def test_rate_limit_delay_without_api_key(self):
        """Paginated requests without API key must sleep between pages."""
        page1 = {
            "totalResults": 2, "resultsPerPage": 1, "startIndex": 0,
            "vulnerabilities": [_cve_item("CVE-2023-0001")],
        }
        page2 = {
            "totalResults": 2, "resultsPerPage": 1, "startIndex": 1,
            "vulnerabilities": [_cve_item("CVE-2023-0002")],
        }
        responses = [MagicMock(status_code=200), MagicMock(status_code=200)]
        responses[0].json.return_value = page1
        responses[1].json.return_value = page2

        env = {k: v for k, v in __import__("os").environ.items() if k != "NVD_API_KEY"}
        with patch("src.nvd.client.requests.get", side_effect=responses), \
             patch("src.nvd.client.time.sleep") as mock_sleep, \
             patch.dict("os.environ", env, clear=True):
            client = NVDClient()
            client.fetch_bitcoin_cves()

        mock_sleep.assert_called()

    def test_http_403_raises_nvd_api_error(self):
        mock_resp = MagicMock(status_code=403, text="Forbidden")
        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            client = NVDClient()
            with pytest.raises(NVDAPIError) as exc_info:
                client.fetch_bitcoin_cves()
        assert exc_info.value.status_code == 403

    def test_timeout_raises_nvd_api_error(self):
        with patch("src.nvd.client.requests.get", side_effect=requests.Timeout):
            client = NVDClient()
            with pytest.raises(NVDAPIError) as exc_info:
                client.fetch_bitcoin_cves()
        assert "timed out" in str(exc_info.value).lower()


class TestNVDClientMapping:
    def test_cvss_v3_priority(self):
        item = _cve_item("CVE-2023-0001", score=9.8, severity="CRITICAL")
        item["cve"]["metrics"]["cvssMetricV2"] = [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]

        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = _nvd_response(1, [item])

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            entries = NVDClient().fetch_bitcoin_cves()

        assert entries[0].severity == "CRITICAL"
        assert entries[0].cvss_score == 9.8

    def test_missing_cvss_with_bitcoin_cpe_defaults_to_unknown(self):
        item = {"cve": {
            "id": "CVE-2023-9999",
            "published": "2023-01-01T00:00:00.000",
            "lastModified": "2023-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "No score available"}],
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:bitcoin:bitcoin:0.20.0:*:*:*:*:*:*:*"}
            ]}]}],
        }}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = _nvd_response(1, [item])

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            entries = NVDClient().fetch_bitcoin_cves()

        assert entries[0].severity == "UNKNOWN"
        assert entries[0].cvss_score is None

    def test_exact_version_extracted(self):
        item = _cve_item("CVE-2023-0001")
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = _nvd_response(1, [item])

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            entries = NVDClient().fetch_bitcoin_cves()

        affected = entries[0].affected_versions
        assert len(affected) == 1
        assert affected[0]["version"] == "0.21.0"
        assert affected[0]["cpe"].startswith("cpe:2.3:a:bitcoin:bitcoin:0.21.0:")

    def test_version_range_extracted(self):
        item = _cve_item(
            "CVE-2023-RANGE",
            cpe_matches=[{
                "criteria": "cpe:2.3:a:bitcoin:bitcoin:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "0.20.0",
                "versionEndExcluding": "0.21.2",
            }],
        )
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = _nvd_response(1, [item])

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            entries = NVDClient().fetch_bitcoin_cves()

        affected = entries[0].affected_versions
        assert len(affected) == 1
        assert affected[0].get("start_inc") == "0.20.0"
        assert affected[0].get("end_exc") == "0.21.2"
        assert "version" not in affected[0]

    def test_non_bitcoin_cpe_filtered(self):
        item = _cve_item(
            "CVE-2023-MIXED",
            cpe_matches=[
                {"criteria": "cpe:2.3:a:copay:copay_bitcoin_wallet:*:*:*:*:*:*:*:*"},
                {"criteria": "cpe:2.3:a:bitcoin:bitcoin:0.21.0:*:*:*:*:*:*:*"},
            ],
        )
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = _nvd_response(1, [item])

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            entries = NVDClient().fetch_bitcoin_cves()

        affected = entries[0].affected_versions
        assert len(affected) == 1
        assert affected[0]["cpe"].startswith("cpe:2.3:a:bitcoin:bitcoin:")

    def test_cve_with_only_non_bitcoin_cpe_omitted(self):
        item = _cve_item(
            "CVE-2023-ALIEN",
            cpe_matches=[
                {"criteria": "cpe:2.3:a:copay:copay_bitcoin_wallet:*:*:*:*:*:*:*:*"},
            ],
        )
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = _nvd_response(1, [item])

        with patch("src.nvd.client.requests.get", return_value=mock_resp):
            entries = NVDClient().fetch_bitcoin_cves()

        assert entries == []
