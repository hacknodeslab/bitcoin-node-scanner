"""
Repository classes for database access.
"""

from .node_repository import NodeRepository
from .scan_repository import ScanRepository
from .vulnerability_repository import VulnerabilityRepository
from .scan_job_repository import ScanJobRepository

__all__ = [
    'NodeRepository',
    'ScanRepository',
    'VulnerabilityRepository',
    'ScanJobRepository',
]
