"""
Unit tests for NVDService — cache logic (fresh, stale, empty).
"""
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.db.models import Base, CVEEntry as CVEEntryModel
from src.nvd.models import CVEEntry, NVDAPIError
from src.nvd.service import NVDService


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


def _sample_cve_entry(cve_id: str = "CVE-2023-0001", fetched_at: datetime = None) -> CVEEntryModel:
    return CVEEntryModel(
        cve_id=cve_id,
        published=datetime(2023, 1, 15),
        last_modified=datetime(2023, 6, 1),
        severity="HIGH",
        cvss_score=7.5,
        description="Test vulnerability",
        affected_versions=json.dumps(["cpe:2.3:a:bitcoin:bitcoin:0.21.0:*"]),
        fetched_at=fetched_at or datetime.utcnow(),
    )


def _mock_client_entries() -> list:
    return [
        CVEEntry(
            cve_id="CVE-2023-NEW",
            published=datetime(2023, 3, 1),
            last_modified=datetime(2023, 3, 2),
            severity="CRITICAL",
            cvss_score=9.8,
            description="New critical vuln",
            affected_versions=["cpe:2.3:a:bitcoin:bitcoin:0.22.0:*"],
        )
    ]


class TestNVDServiceCache:
    def test_fresh_cache_skips_fetch(self, db_session):
        """When cache is fresh, NVD API should NOT be called."""
        db_session.add(_sample_cve_entry(fetched_at=datetime.utcnow()))
        db_session.commit()

        with patch("src.nvd.service.NVDClient") as MockClient:
            service = NVDService(db_session)
            result = service.get_vulnerabilities()

        MockClient.return_value.fetch_bitcoin_cves.assert_not_called()
        assert len(result) == 1

    def test_stale_cache_triggers_fetch(self, db_session):
        """When cache is older than TTL, NVD API should be called."""
        old_time = datetime.utcnow() - timedelta(hours=25)
        db_session.add(_sample_cve_entry(fetched_at=old_time))
        db_session.commit()

        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.return_value = _mock_client_entries()
            service = NVDService(db_session)
            result = service.get_vulnerabilities()

        MockClient.return_value.fetch_bitcoin_cves.assert_called_once()
        # The upserted entry should now be present
        assert any(e.cve_id == "CVE-2023-NEW" for e in result)

    def test_empty_cache_triggers_fetch(self, db_session):
        """When cache is empty, NVD API must be called before returning."""
        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.return_value = _mock_client_entries()
            service = NVDService(db_session)
            result = service.get_vulnerabilities()

        MockClient.return_value.fetch_bitcoin_cves.assert_called_once()
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2023-NEW"

    def test_upsert_updates_existing_record(self, db_session):
        """Refresh should update an existing CVE entry rather than duplicate it."""
        db_session.add(_sample_cve_entry(
            cve_id="CVE-2023-0001",
            fetched_at=datetime.utcnow() - timedelta(hours=25),
        ))
        db_session.commit()

        updated_entry = CVEEntry(
            cve_id="CVE-2023-0001",
            published=datetime(2023, 1, 15),
            last_modified=datetime(2023, 9, 1),
            severity="CRITICAL",  # changed
            cvss_score=9.1,       # changed
            description="Updated description",
            affected_versions=[],
        )
        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.return_value = [updated_entry]
            service = NVDService(db_session)
            service.get_vulnerabilities()

        entries = db_session.query(CVEEntryModel).filter_by(cve_id="CVE-2023-0001").all()
        assert len(entries) == 1
        assert entries[0].severity == "CRITICAL"
        assert entries[0].cvss_score == 9.1

    def test_sort_order_cvss_desc_nulls_last(self, db_session):
        """Results must be sorted by cvss_score DESC with NULLs last."""
        db_session.add(_sample_cve_entry("CVE-A", fetched_at=datetime.utcnow()))
        db_session.query(CVEEntryModel).filter_by(cve_id="CVE-A").update({"cvss_score": 5.0})

        e_high = CVEEntryModel(
            cve_id="CVE-B", severity="CRITICAL", cvss_score=9.8,
            description="High", affected_versions="[]",
            fetched_at=datetime.utcnow(),
        )
        e_null = CVEEntryModel(
            cve_id="CVE-C", severity="UNKNOWN", cvss_score=None,
            description="No score", affected_versions="[]",
            fetched_at=datetime.utcnow(),
        )
        db_session.add_all([e_high, e_null])
        db_session.commit()

        with patch("src.nvd.service.NVDClient"):
            service = NVDService(db_session)
            result = service.get_vulnerabilities()

        scores = [e.cvss_score for e in result]
        non_null = [s for s in scores if s is not None]
        assert non_null == sorted(non_null, reverse=True), "Non-null scores must be DESC"
        assert scores[-1] is None, "NULL score must be last"

    def test_nvd_error_raised_when_cache_empty(self, db_session):
        """If NVD API fails and cache is empty, NVDAPIError propagates."""
        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.side_effect = NVDAPIError("NVD down", 503)
            service = NVDService(db_session)
            with pytest.raises(NVDAPIError):
                service.get_vulnerabilities()
