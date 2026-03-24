"""
Repository classes for database access.
"""

from .node_repository import NodeRepository
from .scan_repository import ScanRepository
from .vulnerability_repository import VulnerabilityRepository

__all__ = [
    'NodeRepository',
    'ScanRepository',
    'VulnerabilityRepository',
]
