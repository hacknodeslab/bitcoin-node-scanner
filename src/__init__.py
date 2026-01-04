"""
Bitcoin Node Security Scanner
HackNodes Lab

A comprehensive security assessment tool for Bitcoin nodes exposed on the clearnet.
"""

__version__ = "1.0.0"
__author__ = "HackNodes Lab"
__email__ = "security@hacknodes.com"

from .scanner import BitcoinNodeScanner, Config

__all__ = ['BitcoinNodeScanner', 'Config']
