"""
Unit tests for GeoIPService and GeoRecord.
"""
import os
from unittest.mock import MagicMock, patch

import pytest

from src.geoip import GeoIPService, GeoRecord, _is_private


class TestIsPrivate:
    def test_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_rfc1918_10(self):
        assert _is_private("10.0.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private("192.168.1.1") is True

    def test_rfc1918_172(self):
        assert _is_private("172.16.0.1") is True

    def test_public_ip(self):
        assert _is_private("8.8.8.8") is False

    def test_public_ip2(self):
        assert _is_private("1.1.1.1") is False


class TestGeoIPServiceDegradation:
    def test_returns_none_when_db_dir_missing(self, tmp_path):
        svc = GeoIPService(db_dir=str(tmp_path))  # empty dir — no .mmdb files
        result = svc.lookup("8.8.8.8")
        assert result is None

    def test_returns_none_for_private_ip_even_with_dbs(self, tmp_path):
        svc = GeoIPService(db_dir=str(tmp_path))
        assert svc.lookup("192.168.1.1") is None
        assert svc.lookup("10.0.0.1") is None
        assert svc.lookup("127.0.0.1") is None

    def test_no_exception_when_db_dir_does_not_exist(self):
        svc = GeoIPService(db_dir="/nonexistent/path/to/dbs")
        result = svc.lookup("8.8.8.8")
        assert result is None  # fail-open


class TestGeoIPServiceWithMockedReaders:
    """Tests using mocked geoip2 readers to avoid needing real .mmdb files."""

    def _make_city_response(self, country_iso="US", country_name="United States",
                             city="Mountain View", subdivision="California",
                             lat=37.386, lon=-122.0838):
        resp = MagicMock()
        resp.country.iso_code = country_iso
        resp.country.name = country_name
        resp.city.name = city
        resp.subdivisions.most_specific.name = subdivision
        resp.subdivisions.__bool__ = lambda s: True
        resp.location.latitude = lat
        resp.location.longitude = lon
        return resp

    def _make_asn_response(self, number=15169, org="Google LLC"):
        resp = MagicMock()
        resp.autonomous_system_number = number
        resp.autonomous_system_organization = org
        return resp

    def test_lookup_returns_geo_record(self, tmp_path):
        # Create dummy .mmdb files so file-existence check passes
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"dummy")
        (tmp_path / "GeoLite2-ASN.mmdb").write_bytes(b"dummy")

        city_resp = self._make_city_response()
        asn_resp = self._make_asn_response()

        svc = GeoIPService(db_dir=str(tmp_path))
        with patch("geoip2.database.Reader") as MockReader:
            city_reader = MagicMock()
            asn_reader = MagicMock()
            city_reader.city.return_value = city_resp
            asn_reader.asn.return_value = asn_resp
            MockReader.side_effect = [city_reader, asn_reader]

            svc._initialized = False  # reset so init runs again
            result = svc.lookup("8.8.8.8")

        assert isinstance(result, GeoRecord)
        assert result.country_code == "US"
        assert result.country_name == "United States"
        assert result.city == "Mountain View"
        assert result.subdivision == "California"
        assert result.latitude == pytest.approx(37.386)
        assert result.longitude == pytest.approx(-122.0838)
        assert result.asn == "AS15169"
        assert result.asn_name == "Google LLC"

    def test_lookup_returns_none_when_nothing_found(self, tmp_path):
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"dummy")
        (tmp_path / "GeoLite2-ASN.mmdb").write_bytes(b"dummy")

        svc = GeoIPService(db_dir=str(tmp_path))
        with patch("geoip2.database.Reader") as MockReader:
            city_reader = MagicMock()
            asn_reader = MagicMock()
            # Both readers raise exception — IP not found
            city_reader.city.side_effect = Exception("not found")
            asn_reader.asn.side_effect = Exception("not found")
            MockReader.side_effect = [city_reader, asn_reader]

            svc._initialized = False
            result = svc.lookup("255.255.255.255")

        assert result is None
