"""Data models and exceptions for the NVD API client."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


class NVDAPIError(Exception):
    """Raised when the NVD API returns an error or is unreachable."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class CVEEntry:
    """Internal representation of a CVE entry fetched from the NVD API."""
    cve_id: str
    published: Optional[datetime]
    last_modified: Optional[datetime]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: Optional[float]
    description: str
    affected_versions: List[str] = field(default_factory=list)
