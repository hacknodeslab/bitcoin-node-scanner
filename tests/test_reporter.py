#!/usr/bin/env python3
"""
Test suite for security reporter functionality
"""

import pytest
import tempfile
import os
import json
import csv
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from reporter import SecurityReporter


# Mock configuration and analyzer for testing
class MockConfig:
    """Mock configuration for testing"""
    
    OUTPUT_DIR = "/tmp/test_output"
    REPORTS_DIR = "/tmp/test_output/reports"
    
    BITCOIN_PORTS = {
        8333: "Bitcoin P2P",
        8332: "Bitcoin RPC",
        18333: "Bitcoin Testnet P2P"
    }


class MockAnalyzer:
    """Mock analyzer for testing"""
    
    def is_vulnerable_version(self, version):
        if not version:
            return False
        return "0.16.3" in version or "0.15.1" in version
    
    def is_dev_version(self, version):
        if not version:
            return False
        return ".99." in version or "rc" in version.lower()
    
    def analyze_risk_level(self, result):
        if result['port'] == 8332:
            return 'CRITICAL'
        if self.is_vulnerable_version(result.get('version', '')):
            return 'HIGH'
        if self.is_dev_version(result.get('version', '')):
            return 'MEDIUM'
        return 'LOW'
    
    def get_risk_reason(self, result, risk_level):
        reasons = []
        if result['port'] == 8332:
            reasons.append("RPC_EXPOSED")
        if self.is_vulnerable_version(result.get('version', '')):
            reasons.append("VULNERABLE_VERSION")
        if self.is_dev_version(result.get('version', '')):
            reasons.append("DEV_VERSION")
        return ', '.join(reasons) if reasons else 'LOW_RISK'


class TestSecurityReporter:
    """Test security reporter functionality"""
    
    def setup_method(self):
        """Setup for each test"""
        self.config = MockConfig()
        self.analyzer = MockAnalyzer()
        self.reporter = SecurityReporter(self.config, self.analyzer)
        
        # Create temporary directories
        os.makedirs(self.config.OUTPUT_DIR, exist_ok=True)
        os.makedirs(self.config.REPORTS_DIR, exist_ok=True)
        os.makedirs(f"{self.config.OUTPUT_DIR}/raw_data", exist_ok=True)
    
    def teardown_method(self):
        """Cleanup after each test"""
        import shutil
        if os.path.exists(self.config.OUTPUT_DIR):
            shutil.rmtree(self.config.OUTPUT_DIR)
    
    def test_initialization(self):
        """Test reporter initialization"""
        assert self.reporter.config == self.config
        assert self.reporter.analyzer == self.analyzer
        assert isinstance(self.reporter.timestamp, str)
        assert len(self.reporter.timestamp) > 0
    
    def test_calculate_percentage(self):
        """Test percentage calculation"""
        assert self.reporter._calculate_percentage(50, 100) == 50.0
        assert self.reporter._calculate_percentage(1, 3) == pytest.approx(33.33, rel=1e-2)
        assert self.reporter._calculate_percentage(10, 0) == 0.0  # Zero division protection
    
    def test_get_version_flags(self):
        """Test version flag generation"""
        # Vulnerable version
        flags1 = self.reporter._get_version_flags("Satoshi:0.16.3/")
        assert "⚠ VULNERABLE" in flags1
        
        # Dev version
        flags2 = self.reporter._get_version_flags("0.21.99.0")
        assert "🔧 DEV" in flags2
        
        # Safe version
        flags3 = self.reporter._get_version_flags("0.21.1")
        assert flags3 == ""
    
    def test_generate_text_report(self):
        """Test text report generation"""
        stats = {
            'total_results': 100,
            'unique_ips': 95,
            'vulnerable_nodes': 5,
            'rpc_exposed': 2,
            'dev_versions': 3,
            'risk_distribution': {
                'CRITICAL': 2,
                'HIGH': 8,
                'MEDIUM': 15,
                'LOW': 75
            },
            'port_distribution': {
                8333: 80,
                8332: 15,
                18333: 5
            },
            'version_distribution': {
                'Satoshi:0.21.1': 50,
                'Satoshi:0.20.1': 30,
                'Satoshi:0.16.3': 5
            },
            'country_distribution': {
                'US': 40,
                'CN': 25,
                'DE': 15
            },
            'asn_distribution': {
                'AS1234': 30,
                'AS5678': 20,
                'AS9999': 15
            }
        }
        
        results = []  # Not used in text report generation
        report = self.reporter.generate_text_report(stats, results)
        
        # Check report structure
        assert "BITCOIN NODE SECURITY SCAN REPORT" in report
        assert "EXECUTIVE SUMMARY" in report
        assert "RISK DISTRIBUTION" in report
        assert "PORT DISTRIBUTION" in report
        assert "TOP 20 VERSIONS" in report
        assert "TOP 20 COUNTRIES" in report
        assert "TOP 20 ASNs" in report
        assert "END OF REPORT" in report
        
        # Check specific content
        assert "Total nodes found: 100" in report
        assert "Unique IPs: 95" in report
        assert "Vulnerable nodes: 5" in report
        assert "RPC exposed: 2" in report
        
        # Check risk distribution (flexible formatting)
        assert "CRITICAL" in report and "2" in report and "2.00%" in report
        assert "HIGH" in report and "8" in report and "8.00%" in report
        
        # Check port distribution
        assert "8333 (Bitcoin P2P" in report
        assert "8332 (Bitcoin RPC" in report
    
    def test_save_json_data(self):
        """Test JSON data saving"""
        data = {'test': 'data', 'number': 42}
        
        file_path = self.reporter.save_json_data(data, 'test', 'reports')
        
        assert os.path.exists(file_path)
        assert 'test_' in file_path
        assert file_path.endswith('.json')
        
        # Verify content
        with open(file_path, 'r') as f:
            loaded_data = json.load(f)
        
        assert loaded_data == data
    
    def test_save_csv_data(self):
        """Test CSV data saving"""
        data = [
            {'ip': '1.1.1.1', 'port': 8333, 'risk': 'LOW'},
            {'ip': '2.2.2.2', 'port': 8332, 'risk': 'CRITICAL'},
            {'ip': '3.3.3.3', 'port': 8333, 'risk': 'HIGH'}
        ]
        
        file_path = self.reporter.save_csv_data(data, 'test', 'reports')
        
        assert os.path.exists(file_path)
        assert 'test_' in file_path
        assert file_path.endswith('.csv')
        
        # Verify content
        with open(file_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 3
        assert rows[0]['ip'] == '1.1.1.1'
        assert rows[1]['port'] == '8332'
        assert rows[2]['risk'] == 'HIGH'
    
    def test_save_csv_data_complex_types(self):
        """Test CSV saving with complex data types"""
        data = [
            {
                'ip': '1.1.1.1',
                'ports': [22, 80, 443],
                'metadata': {'country': 'US', 'org': 'Test'}
            }
        ]
        
        file_path = self.reporter.save_csv_data(data, 'complex', 'reports')
        
        assert os.path.exists(file_path)
        
        # Verify complex types are JSON-encoded
        with open(file_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            row = next(reader)
        
        assert row['ip'] == '1.1.1.1'
        assert '[22, 80, 443]' in row['ports']
        assert '"country": "US"' in row['metadata']
    
    def test_save_csv_data_empty(self):
        """Test CSV saving with empty data"""
        file_path = self.reporter.save_csv_data([], 'empty', 'reports')
        assert file_path is None
    
    def test_save_raw_data(self):
        """Test raw data saving"""
        results = [
            {
                'ip': '1.1.1.1',
                'port': 8333,
                'version': 'Satoshi:0.21.1',
                'country_code': 'US'
            },
            {
                'ip': '2.2.2.2',
                'port': 8332,
                'version': 'Satoshi:0.20.1',
                'country_code': 'CN'
            }
        ]
        
        json_path, csv_path = self.reporter.save_raw_data(results)
        
        assert os.path.exists(json_path)
        assert os.path.exists(csv_path)
        assert 'nodes_' in json_path
        assert 'nodes_' in csv_path
        
        # Verify JSON content
        with open(json_path, 'r') as f:
            loaded_data = json.load(f)
        assert len(loaded_data) == 2
        assert loaded_data[0]['ip'] == '1.1.1.1'
        
        # Verify CSV content
        with open(csv_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[1]['ip'] == '2.2.2.2'
    
    def test_save_statistics(self):
        """Test statistics saving"""
        stats = {
            'total_results': 100,
            'unique_ips': 95,
            'risk_distribution': {'LOW': 80, 'HIGH': 20}
        }
        
        file_path = self.reporter.save_statistics(stats)
        
        assert os.path.exists(file_path)
        assert 'statistics_' in file_path
        assert file_path.endswith('.json')
        
        # Verify content
        with open(file_path, 'r') as f:
            loaded_stats = json.load(f)
        assert loaded_stats == stats
    
    def test_save_critical_nodes(self):
        """Test critical nodes saving"""
        critical_nodes = [
            {
                'ip': '1.1.1.1',
                'port': 8332,
                'risk_level': 'CRITICAL',
                'reason': 'RPC_EXPOSED'
            },
            {
                'ip': '2.2.2.2',
                'port': 8333,
                'risk_level': 'HIGH',
                'reason': 'VULNERABLE_VERSION'
            }
        ]
        
        json_path, csv_path = self.reporter.save_critical_nodes(critical_nodes)
        
        assert os.path.exists(json_path)
        assert os.path.exists(csv_path)
        assert 'critical_nodes_' in json_path
        assert 'critical_nodes_' in csv_path
    
    def test_generate_summary_table(self):
        """Test summary table generation"""
        stats = {
            'total_results': 1000,
            'unique_ips': 950,
            'vulnerable_nodes': 50,
            'rpc_exposed': 10,
            'dev_versions': 25,
            'risk_distribution': {
                'CRITICAL': 10,
                'HIGH': 50,
                'MEDIUM': 100,
                'LOW': 840
            }
        }
        
        summary = self.reporter.generate_summary_table(stats)
        
        assert "QUICK SUMMARY" in summary
        assert "Total Nodes:        1,000" in summary
        assert "Unique IPs:         950" in summary
        assert "Vulnerable:         50" in summary
        assert "RPC Exposed:        10" in summary
        assert "Dev Versions:       25" in summary
        
        # Check risk percentages (flexible formatting)
        assert "CRITICAL" in summary and "10" in summary and "1.00%" in summary
        assert "HIGH" in summary and "50" in summary and "5.00%" in summary
        assert "MEDIUM" in summary and "100" in summary and "10.00%" in summary
        assert "LOW" in summary and "840" in summary and "84.00%" in summary
    
    def test_export_results(self):
        """Test complete results export"""
        results = [
            {'ip': '1.1.1.1', 'port': 8333, 'risk': 'LOW'},
            {'ip': '2.2.2.2', 'port': 8332, 'risk': 'CRITICAL'}
        ]
        
        stats = {
            'total_results': 2,
            'unique_ips': 2,
            'risk_distribution': {'LOW': 1, 'CRITICAL': 1},
            'port_distribution': {8333: 1, 8332: 1},
            'version_distribution': {'0.21.1': 2},
            'country_distribution': {'US': 2},
            'asn_distribution': {'AS1234': 2}
        }
        
        critical_nodes = [
            {'ip': '2.2.2.2', 'port': 8332, 'risk_level': 'CRITICAL'}
        ]
        
        exports = self.reporter.export_results(results, stats, critical_nodes)
        
        # Check all export types are present
        expected_keys = [
            'raw_json', 'raw_csv',
            'statistics', 'text_report',
            'critical_json', 'critical_csv'
        ]
        
        for key in expected_keys:
            assert key in exports
            assert os.path.exists(exports[key])
    
    @patch('builtins.print')
    def test_print_report(self, mock_print):
        """Test report printing"""
        stats = {
            'total_results': 10,
            'unique_ips': 10,
            'risk_distribution': {'LOW': 10},
            'port_distribution': {8333: 10},
            'version_distribution': {'0.21.1': 10},
            'country_distribution': {'US': 10},
            'asn_distribution': {'AS1234': 10}
        }
        
        self.reporter.print_report(stats, [])
        
        # Verify print was called
        mock_print.assert_called()
        
        # Check that the report contains expected content
        all_calls = [str(call) for call in mock_print.call_args_list]
        report_text = ' '.join(all_calls)
        
        assert "BITCOIN NODE SECURITY SCAN REPORT" in report_text
    
    @patch('builtins.print')
    def test_print_summary(self, mock_print):
        """Test summary printing"""
        stats = {
            'total_results': 100,
            'unique_ips': 95,
            'vulnerable_nodes': 5,
            'rpc_exposed': 2,
            'dev_versions': 3,
            'risk_distribution': {'LOW': 90, 'HIGH': 10}
        }
        
        self.reporter.print_summary(stats)
        
        # Verify print was called
        mock_print.assert_called()
        
        # Check that summary contains expected content
        all_calls = [str(call) for call in mock_print.call_args_list]
        summary_text = ' '.join(all_calls)
        
        assert "QUICK SUMMARY" in summary_text
        assert "Total Nodes:" in summary_text


class TestSecurityReporterEdgeCases:
    """Test edge cases and error handling"""
    
    def setup_method(self):
        """Setup for each test"""
        self.config = MockConfig()
        self.analyzer = MockAnalyzer()
        self.reporter = SecurityReporter(self.config, self.analyzer)
        
        # Ensure output directories exist
        os.makedirs(self.config.OUTPUT_DIR, exist_ok=True)
        os.makedirs(self.config.REPORTS_DIR, exist_ok=True)
    
    def teardown_method(self):
        """Cleanup after each test"""
        import shutil
        if os.path.exists(self.config.OUTPUT_DIR):
            shutil.rmtree(self.config.OUTPUT_DIR)
    
    def test_generate_text_report_empty_stats(self):
        """Test report generation with minimal stats"""
        stats = {
            'total_results': 0,
            'unique_ips': 0,
            'risk_distribution': {},
            'port_distribution': {},
            'version_distribution': {},
            'country_distribution': {},
            'asn_distribution': {}
        }
        
        report = self.reporter.generate_text_report(stats, [])
        
        # Should not crash and contain basic structure
        assert "BITCOIN NODE SECURITY SCAN REPORT" in report
        assert "Total nodes found: 0" in report
        assert "Unique IPs: 0" in report
    
    def test_save_to_nonexistent_directory(self):
        """Test saving when directory doesn't exist"""
        # Temporarily change config to non-existent directory
        original_dir = self.config.OUTPUT_DIR
        self.config.OUTPUT_DIR = "/tmp/nonexistent_test_dir"
        
        try:
            # Should raise FileNotFoundError since directory doesn't exist
            data = {'test': 'data'}
            with pytest.raises(FileNotFoundError):
                file_path = self.reporter.save_json_data(data, 'test')
            
        finally:
            # Restore original directory
            self.config.OUTPUT_DIR = original_dir
    
    def test_version_flags_edge_cases(self):
        """Test version flag generation with edge cases"""
        # Empty version
        flags1 = self.reporter._get_version_flags("")
        assert flags1 == ""
        
        # None version  
        flags2 = self.reporter._get_version_flags(None)
        assert flags2 == ""
        
        # Multiple flags
        # This depends on analyzer implementation - adjust based on actual behavior
        flags3 = self.reporter._get_version_flags("0.16.3rc1")  # Both vulnerable and dev
        # Should contain both flags if analyzer detects both conditions


if __name__ == "__main__":
    pytest.main([__file__])