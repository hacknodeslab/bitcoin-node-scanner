#!/usr/bin/env python3
"""
Test suite for security analyzer functionality
"""

import pytest
import os
from unittest.mock import MagicMock

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzer import SecurityAnalyzer


# Mock configuration class for testing
class MockConfig:
    """Mock configuration for testing"""
    
    VULNERABLE_VERSIONS = {
        "0.16.3": "CVE-2018-17144",
        "0.15.1": "CVE-2017-18350",
        "0.14.2": "CVE-2017-12842",
        "0.13.0": "CVE-2016-10724"
    }
    
    HIGH_RISK_PORTS = {
        22: "SSH",
        23: "Telnet", 
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP",
        5900: "VNC",
        8332: "Bitcoin RPC"
    }
    
    BITCOIN_PORTS = {
        8333: "Bitcoin P2P",
        8332: "Bitcoin RPC", 
        18333: "Bitcoin Testnet P2P",
        18332: "Bitcoin Testnet RPC"
    }


class TestSecurityAnalyzer:
    """Test security analyzer functionality"""
    
    def setup_method(self):
        """Setup for each test"""
        self.config = MockConfig()
        self.analyzer = SecurityAnalyzer(self.config)
    
    def test_initialization(self):
        """Test analyzer initialization"""
        assert self.analyzer.config == self.config
    
    def test_is_vulnerable_version_known_vulnerable(self):
        """Test vulnerable version detection for known vulnerabilities"""
        assert self.analyzer.is_vulnerable_version("Satoshi:0.16.3/") == True
        assert self.analyzer.is_vulnerable_version("0.15.1") == True
        assert self.analyzer.is_vulnerable_version("Bitcoin Core:0.14.2") == True
    
    def test_is_vulnerable_version_old_versions(self):
        """Test vulnerable version detection for old versions"""
        assert self.analyzer.is_vulnerable_version("Satoshi:0.20.1/") == True
        assert self.analyzer.is_vulnerable_version("Satoshi:0.19.0/") == True
        assert self.analyzer.is_vulnerable_version("Satoshi:0.10.5/") == True
    
    def test_is_vulnerable_version_safe_versions(self):
        """Test vulnerable version detection for safe versions"""
        assert self.analyzer.is_vulnerable_version("Satoshi:0.21.1/") == False
        assert self.analyzer.is_vulnerable_version("Satoshi:0.22.0/") == False
        assert self.analyzer.is_vulnerable_version("Bitcoin Core:23.0") == False
        assert self.analyzer.is_vulnerable_version("Unknown") == False
    
    def test_is_vulnerable_version_invalid_format(self):
        """Test vulnerable version detection with invalid formats"""
        assert self.analyzer.is_vulnerable_version("invalid:format") == False
        assert self.analyzer.is_vulnerable_version("") == False
        assert self.analyzer.is_vulnerable_version("Satoshi:invalid/") == False
    
    def test_is_dev_version(self):
        """Test development version detection"""
        assert self.analyzer.is_dev_version("0.21.99.0") == True
        assert self.analyzer.is_dev_version("0.22.0rc1") == True
        assert self.analyzer.is_dev_version("0.22.0-beta") == True
        assert self.analyzer.is_dev_version("Bitcoin Core:0.21.99.0") == True
        
        assert self.analyzer.is_dev_version("0.21.1") == False
        assert self.analyzer.is_dev_version("0.22.0") == False
        assert self.analyzer.is_dev_version("Bitcoin Core:23.0") == False
    
    def test_analyze_risk_level_critical_rpc(self):
        """Test risk level analysis for RPC exposed nodes"""
        result = {
            'ip': '192.168.1.1',
            'port': 8332,
            'version': 'Satoshi:0.21.1',
            'country_code': 'US'
        }
        
        assert self.analyzer.analyze_risk_level(result) == 'CRITICAL'
    
    def test_analyze_risk_level_high_vulnerable(self):
        """Test risk level analysis for vulnerable versions"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.16.3/',
            'country_code': 'US'
        }
        
        risk = self.analyzer.analyze_risk_level(result)
        assert risk in ['HIGH', 'MEDIUM']  # Depends on other factors
    
    def test_analyze_risk_level_high_dev_version(self):
        """Test risk level analysis for development versions"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.21.99.0/',
            'country_code': 'US'
        }
        
        risk = self.analyzer.analyze_risk_level(result)
        assert risk in ['HIGH', 'MEDIUM']  # Depends on other factors
    
    def test_analyze_risk_level_high_multiple_services(self):
        """Test risk level analysis for multiple exposed services"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.21.1/',
            'country_code': 'US',
            'enrichment': {
                'all_ports': [22, 23, 80, 443, 3389]  # Multiple high-risk ports
            }
        }
        
        risk = self.analyzer.analyze_risk_level(result)
        assert risk in ['HIGH', 'MEDIUM']
    
    def test_analyze_risk_level_low_safe(self):
        """Test risk level analysis for safe configurations"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.21.1/',
            'country_code': 'US'
        }
        
        assert self.analyzer.analyze_risk_level(result) == 'LOW'
    
    def test_get_risk_reason_rpc(self):
        """Test risk reason for RPC exposure"""
        result = {
            'ip': '192.168.1.1',
            'port': 8332,
            'version': 'Satoshi:0.21.1',
            'country_code': 'US'
        }
        
        reason = self.analyzer.get_risk_reason(result, 'CRITICAL')
        assert 'RPC_EXPOSED' in reason
    
    def test_get_risk_reason_vulnerable_version(self):
        """Test risk reason for vulnerable version"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.16.3/',
            'country_code': 'US'
        }
        
        reason = self.analyzer.get_risk_reason(result, 'HIGH')
        assert 'VULNERABLE_VERSION' in reason
        assert 'CVE-2018-17144' in reason
    
    def test_get_risk_reason_dev_version(self):
        """Test risk reason for development version"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.21.99.0/',
            'country_code': 'US'
        }
        
        reason = self.analyzer.get_risk_reason(result, 'MEDIUM')
        assert 'DEV_VERSION' in reason
    
    def test_get_risk_reason_multiple_services(self):
        """Test risk reason for multiple services"""
        result = {
            'ip': '192.168.1.1',
            'port': 8333,
            'version': 'Satoshi:0.21.1/',
            'country_code': 'US',
            'enrichment': {
                'all_ports': [22, 23, 80]
            }
        }
        
        reason = self.analyzer.get_risk_reason(result, 'HIGH')
        assert 'MULTIPLE_SERVICES' in reason
    
    def test_extract_version_from_banner(self):
        """Test version extraction from various banner formats"""
        # From banner with Satoshi version
        result1 = {'banner': '/Satoshi:0.21.1/Bitcoin Core:0.21.1/'}
        version1 = self.analyzer.extract_version_from_banner(result1)
        assert version1 == "Satoshi:0.21.1"
        
        # From product and version fields
        result2 = {'product': 'Bitcoin Core', 'version': '0.21.1'}
        version2 = self.analyzer.extract_version_from_banner(result2)
        assert version2 == "Bitcoin Core:0.21.1"
        
        # From version field only
        result3 = {'version': '0.21.1'}
        version3 = self.analyzer.extract_version_from_banner(result3)
        assert version3 == "0.21.1"
        
        # Unknown version
        result4 = {}
        version4 = self.analyzer.extract_version_from_banner(result4)
        assert version4 == "Unknown"
    
    def test_generate_statistics(self):
        """Test statistics generation"""
        results = [
            {
                'ip': '1.1.1.1',
                'port': 8333,
                'version': 'Satoshi:0.21.1/',
                'country_code': 'US',
                'asn': 'AS1234'
            },
            {
                'ip': '2.2.2.2',
                'port': 8332,
                'version': 'Satoshi:0.16.3/',
                'country_code': 'CN',
                'asn': 'AS5678'
            },
            {
                'ip': '3.3.3.3',
                'port': 8333,
                'version': 'Satoshi:0.21.99.0/',
                'country_code': 'US',
                'asn': 'AS1234'
            }
        ]
        
        stats = self.analyzer.generate_statistics(results)
        
        # Basic counts
        assert stats['total_results'] == 3
        assert stats['unique_ips'] == 3
        
        # Port distribution
        assert stats['port_distribution'][8333] == 2
        assert stats['port_distribution'][8332] == 1
        
        # Country distribution
        assert stats['country_distribution']['US'] == 2
        assert stats['country_distribution']['CN'] == 1
        
        # ASN distribution
        assert stats['asn_distribution']['AS1234'] == 2
        assert stats['asn_distribution']['AS5678'] == 1
        
        # Version distribution
        assert 'Satoshi:0.21.1/' in stats['version_distribution']
        assert 'Satoshi:0.16.3/' in stats['version_distribution']
        assert 'Satoshi:0.21.99.0/' in stats['version_distribution']
        
        # Risk distribution
        assert 'CRITICAL' in stats['risk_distribution']
        assert 'MEDIUM' in stats['risk_distribution'] or 'HIGH' in stats['risk_distribution']
        
        # Security metrics
        assert stats['vulnerable_nodes'] == 1  # 0.16.3
        assert stats['rpc_exposed'] == 1  # port 8332
        assert stats['dev_versions'] == 1  # 0.21.99.0
    
    def test_identify_critical_nodes(self):
        """Test critical node identification"""
        results = [
            {
                'ip': '1.1.1.1',
                'port': 8333,
                'version': 'Satoshi:0.21.1/',
                'country_code': 'US',
                'organization': 'Test Org 1',
                'asn': 'AS1234'
            },
            {
                'ip': '2.2.2.2',
                'port': 8332,  # RPC = CRITICAL
                'version': 'Satoshi:0.21.1/',
                'country_code': 'CN',
                'organization': 'Test Org 2',
                'asn': 'AS5678'
            },
            {
                'ip': '3.3.3.3',
                'port': 8333,
                'version': 'Satoshi:0.16.3/',  # Vulnerable = HIGH
                'country_code': 'DE',
                'organization': 'Test Org 3',
                'asn': 'AS9999'
            }
        ]
        
        critical_nodes = self.analyzer.identify_critical_nodes(results)
        
        # At least the RPC node should be identified as critical
        assert len(critical_nodes) >= 1
        
        # Should be sorted with CRITICAL first
        assert critical_nodes[0]['risk_level'] == 'CRITICAL'
        assert critical_nodes[0]['ip'] == '2.2.2.2'
        assert critical_nodes[0]['port'] == 8332
        
        # Check if vulnerable node is identified (might be HIGH or MEDIUM depending on implementation)
        vulnerable_node = None
        for node in critical_nodes:
            if node['ip'] == '3.3.3.3':
                vulnerable_node = node
                break
        
        if vulnerable_node:
            assert vulnerable_node['risk_level'] in ['HIGH', 'MEDIUM']
            assert 'VULNERABLE_VERSION' in vulnerable_node['reason']
    
    def test_get_vulnerability_details(self):
        """Test vulnerability detail extraction"""
        # Known vulnerable version
        details1 = self.analyzer.get_vulnerability_details("Satoshi:0.16.3/")
        assert details1['is_vulnerable'] == True
        assert details1['is_dev'] == False
        assert 'CVE-2018-17144' in details1['cves']
        
        # Development version
        details2 = self.analyzer.get_vulnerability_details("0.21.99.0")
        assert details2['is_vulnerable'] == False
        assert details2['is_dev'] == True
        assert details2['cves'] == []
        
        # Safe version
        details3 = self.analyzer.get_vulnerability_details("0.21.1")
        assert details3['is_vulnerable'] == False
        assert details3['is_dev'] == False
        assert details3['cves'] == []


class TestSecurityAnalyzerEdgeCases:
    """Test edge cases and error handling"""
    
    def setup_method(self):
        """Setup for each test"""
        self.config = MockConfig()
        self.analyzer = SecurityAnalyzer(self.config)
    
    def test_analyze_risk_level_missing_fields(self):
        """Test risk analysis with missing fields"""
        result = {
            'ip': '1.1.1.1',
            'port': 8333
            # Missing version, country_code etc.
        }
        
        # Should not crash and return LOW
        risk = self.analyzer.analyze_risk_level(result)
        assert risk == 'LOW'
    
    def test_extract_version_malformed_banner(self):
        """Test version extraction with malformed banners"""
        result = {'banner': 'malformed banner string without proper format'}
        version = self.analyzer.extract_version_from_banner(result)
        assert version == "Unknown"
    
    def test_generate_statistics_empty_results(self):
        """Test statistics generation with empty results"""
        stats = self.analyzer.generate_statistics([])
        
        assert stats['total_results'] == 0
        assert stats['unique_ips'] == 0
        assert stats['port_distribution'] == {}
        assert stats['country_distribution'] == {}
        assert stats['version_distribution'] == {}
        assert stats['asn_distribution'] == {}
        assert stats['risk_distribution'] == {}
        assert stats['vulnerable_nodes'] == 0
        assert stats['rpc_exposed'] == 0
        assert stats['dev_versions'] == 0
    
    def test_identify_critical_nodes_no_critical(self):
        """Test critical node identification with no critical nodes"""
        results = [
            {
                'ip': '1.1.1.1',
                'port': 8333,
                'version': 'Satoshi:0.21.1/',
                'country_code': 'US',
                'organization': 'Test Org',
                'asn': 'AS1234'
            }
        ]
        
        critical_nodes = self.analyzer.identify_critical_nodes(results)
        assert critical_nodes == []
    
    def test_version_parsing_edge_cases(self):
        """Test version parsing with edge cases"""
        # Test various version string formats
        assert self.analyzer.is_vulnerable_version("Satoshi:0.20.1/Bitcoin Core:0.20.1/") == True
        assert self.analyzer.is_vulnerable_version("/Satoshi:0.22.0/") == False
        assert self.analyzer.is_vulnerable_version("0.16.3rc1") == True  # Contains vulnerable version


if __name__ == "__main__":
    pytest.main([__file__])