"""
MaxMind GeoIP2 / GeoLite2 lookup service for Bitcoin Node Scanner.

Usage:
    service = GeoIPService()          # reads GEOIP_DB_DIR env var
    record = service.lookup("1.2.3.4")
    if record:
        print(record.country_code, record.city, record.latitude)

Fails open: if .mmdb files are missing, lookup() returns None and a warning
is logged — the scanner continues normally without geo enrichment.
"""
import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "geoip_dbs")


@dataclass
class GeoRecord:
    """Structured geo data returned by GeoIPService.lookup()."""
    country_code: Optional[str]
    country_name: Optional[str]
    city: Optional[str]
    subdivision: Optional[str]   # region / state
    latitude: Optional[float]
    longitude: Optional[float]
    asn: Optional[str]           # e.g. "AS15169"
    asn_name: Optional[str]      # e.g. "Google LLC"


def _is_private(ip: str) -> bool:
    """Return True for private/loopback/reserved addresses."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


class GeoIPService:
    """
    Offline IP geolocation backed by MaxMind GeoLite2 .mmdb files.

    Readers are opened lazily on first use and kept open for the lifetime
    of the service instance (efficient for batch lookups).
    """

    CITY_DB = "GeoLite2-City.mmdb"
    ASN_DB = "GeoLite2-ASN.mmdb"

    def __init__(self, db_dir: Optional[str] = None):
        self._db_dir = db_dir or os.getenv("GEOIP_DB_DIR", _DEFAULT_DB_DIR)
        self._city_reader = None
        self._asn_reader = None
        self._initialized = False
        self._available = False

    def _init_readers(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        try:
            import geoip2.database  # noqa: PLC0415
        except ImportError:
            logger.warning("geoip2 package not installed. Run: pip install geoip2")
            return

        city_path = os.path.join(self._db_dir, self.CITY_DB)
        asn_path = os.path.join(self._db_dir, self.ASN_DB)

        missing = [p for p in (city_path, asn_path) if not os.path.isfile(p)]
        if missing:
            logger.warning(
                "MaxMind GeoIP databases not found: %s. "
                "Run scripts/download_geoip_dbs.sh to download them. "
                "Geo enrichment will be skipped.",
                missing,
            )
            return

        try:
            self._city_reader = geoip2.database.Reader(city_path)
            self._asn_reader = geoip2.database.Reader(asn_path)
            self._available = True
            logger.info("MaxMind GeoIP databases loaded from %s", self._db_dir)
        except Exception as exc:
            logger.warning("Failed to open MaxMind databases: %s", exc)

    def lookup(self, ip: str) -> Optional[GeoRecord]:
        """
        Look up geo data for an IP address.

        Returns None for private/reserved IPs, unknown IPs, or when
        .mmdb files are unavailable.
        """
        if _is_private(ip):
            return None

        self._init_readers()
        if not self._available:
            return None

        country_code = country_name = city = subdivision = None
        latitude = longitude = None
        asn = asn_name = None

        if self._city_reader:
            try:
                city_resp = self._city_reader.city(ip)
                country_code = city_resp.country.iso_code
                country_name = city_resp.country.name
                city = city_resp.city.name
                if city_resp.subdivisions:
                    subdivision = city_resp.subdivisions.most_specific.name
                if city_resp.location.latitude is not None:
                    latitude = city_resp.location.latitude
                    longitude = city_resp.location.longitude
            except Exception as e:
                logger.warning("Error looking up city for %s: %s", ip, e)

        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(ip)
                asn = f"AS{asn_resp.autonomous_system_number}"
                asn_name = asn_resp.autonomous_system_organization
            except Exception as e:
                logger.warning("Error looking up ASN for %s: %s", ip, e)

        # Return None if nothing was found at all
        if all(v is None for v in (country_code, city, asn)):
            return None

        return GeoRecord(
            country_code=country_code,
            country_name=country_name,
            city=city,
            subdivision=subdivision,
            latitude=latitude,
            longitude=longitude,
            asn=asn,
            asn_name=asn_name,
        )

    def close(self) -> None:
        """Close database readers and free resources."""
        if self._city_reader:
            self._city_reader.close()
            self._city_reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None
        self._available = False
        self._initialized = False
