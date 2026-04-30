"""Unit tests for CVEMatcher."""
import json

from src.db.models import CVEEntry
from src.nvd.matcher import CVEMatcher


def _entry(cve_id: str, affected: list[dict]) -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        severity="HIGH",
        affected_versions=json.dumps(affected),
    )


class TestCVEMatcher:
    def test_exact_version_match(self):
        m = CVEMatcher([
            _entry("CVE-X", [{"cpe": "...", "version": "0.21.0"}]),
        ])
        assert m.matches_for("0.21.0") == {"CVE-X"}
        assert m.matches_for("0.21.1") == set()

    def test_version_in_closed_range(self):
        m = CVEMatcher([
            _entry("CVE-RANGE", [{
                "cpe": "...", "start_inc": "0.20.0", "end_exc": "0.21.2",
            }]),
        ])
        assert m.matches_for("0.20.0") == {"CVE-RANGE"}
        assert m.matches_for("0.21.0") == {"CVE-RANGE"}
        assert m.matches_for("0.21.1") == {"CVE-RANGE"}

    def test_excluding_bound_does_not_match(self):
        m = CVEMatcher([
            _entry("CVE-RANGE", [{
                "cpe": "...", "start_inc": "0.20.0", "end_exc": "0.21.2",
            }]),
        ])
        # end_exc 0.21.2 → 0.21.2 itself must NOT match
        assert m.matches_for("0.21.2") == set()
        # before start is also out
        assert m.matches_for("0.19.99") == set()

    def test_start_excluding_bound(self):
        m = CVEMatcher([
            _entry("CVE-SE", [{
                "cpe": "...", "start_exc": "0.20.0", "end_inc": "0.21.0",
            }]),
        ])
        assert m.matches_for("0.20.0") == set()  # excluded
        assert m.matches_for("0.20.1") == {"CVE-SE"}
        assert m.matches_for("0.21.0") == {"CVE-SE"}  # included

    def test_unbounded_catch_all_only_when_no_specific_entry(self):
        m = CVEMatcher([
            _entry("CVE-CATCHALL", [{"cpe": "..."}]),  # no version, no range
            _entry("CVE-SPECIFIC", [
                {"cpe": "...", "version": "0.21.0"},
                {"cpe": "..."},  # this catch-all should be ignored because of the specific entry
            ]),
        ])
        assert m.matches_for("0.21.0") == {"CVE-CATCHALL", "CVE-SPECIFIC"}
        assert m.matches_for("0.21.1") == {"CVE-CATCHALL"}

    def test_unparseable_version_returns_empty(self):
        m = CVEMatcher([
            _entry("CVE-X", [{"cpe": "...", "version": "0.21.0"}]),
        ])
        assert m.matches_for("not-a-version") == set()
        assert m.matches_for(None) == set()
        assert m.matches_for("") == set()
        assert m.matches_for("Satoshi:dev-build") == set()

    def test_multiple_ranges_same_cve(self):
        m = CVEMatcher([
            _entry("CVE-MULTI", [
                {"cpe": "...", "start_inc": "0.18.0", "end_exc": "0.19.0"},
                {"cpe": "...", "start_inc": "0.21.0", "end_exc": "0.22.0"},
            ]),
        ])
        assert m.matches_for("0.18.5") == {"CVE-MULTI"}
        assert m.matches_for("0.20.0") == set()
        assert m.matches_for("0.21.5") == {"CVE-MULTI"}

    def test_exact_and_range_share_cve(self):
        m = CVEMatcher([
            _entry("CVE-X", [
                {"cpe": "...", "version": "0.20.0"},
                {"cpe": "...", "start_inc": "0.21.0", "end_inc": "0.21.5"},
            ]),
        ])
        assert m.matches_for("0.20.0") == {"CVE-X"}
        assert m.matches_for("0.21.3") == {"CVE-X"}
        assert m.matches_for("0.22.0") == set()

    def test_invalid_json_skipped(self):
        # Manually inject a row with broken affected_versions
        bad = CVEEntry(cve_id="CVE-BAD", severity="LOW", affected_versions="{not json")
        good = _entry("CVE-OK", [{"cpe": "...", "version": "0.21.0"}])
        m = CVEMatcher([bad, good])
        assert m.matches_for("0.21.0") == {"CVE-OK"}

    def test_empty_catalog(self):
        m = CVEMatcher([])
        assert m.matches_for("0.21.0") == set()
        assert m.cve_count == 0
