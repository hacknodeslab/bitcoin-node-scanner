#!/usr/bin/env python3
"""
Test suite for Bitcoin Node Scanner
"""

import pytest
import os
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timedelta

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ============================================================================
# Config Tests
# ============================================================================

class TestConfig:
    """Test Config class"""

    def test_default_queries(self):
        from scanner import Config
        assert isinstance(Config.QUERIES, list)
        assert len(Config.QUERIES) > 0

    def test_bitcoin_ports(self):
        from scanner import Config
        assert 8333 in Config.BITCOIN_PORTS
        assert 8332 in Config.BITCOIN_PORTS
        assert Config.BITCOIN_PORTS[8332] == 'RPC Mainnet (CRITICAL)'

    def test_high_risk_ports(self):
        from scanner import Config
        assert 22 in Config.HIGH_RISK_PORTS
        assert 3306 in Config.HIGH_RISK_PORTS

    def test_vulnerable_versions(self):
        from scanner import Config
        assert '0.15.0' in Config.VULNERABLE_VERSIONS
        assert '0.16.0' in Config.VULNERABLE_VERSIONS
        assert 'CVE-2018-17144' in Config.VULNERABLE_VERSIONS['0.15.0']

    def test_output_directories(self):
        from scanner import Config
        assert Config.OUTPUT_DIR == 'output'
        assert 'raw_data' in Config.RAW_DATA_DIR
        assert 'reports' in Config.REPORTS_DIR
        assert 'logs' in Config.LOGS_DIR

    def test_queries_are_strings(self):
        from scanner import Config
        for q in Config.QUERIES:
            assert isinstance(q, str)
            assert len(q.strip()) > 0


# ============================================================================
# BitcoinNodeScanner Tests
# ============================================================================

class TestBitcoinNodeScanner:
    """Test BitcoinNodeScanner class"""

    def _make_scanner(self, tmp_path):
        """Helper to create a scanner with mocked Shodan API.
        
        Patches Config directories persistently so they remain active
        during subsequent method calls on the returned scanner.
        """
        import scanner as scanner_mod

        self._patchers = [
            patch.object(scanner_mod.Config, 'OUTPUT_DIR', str(tmp_path / 'output')),
            patch.object(scanner_mod.Config, 'RAW_DATA_DIR', str(tmp_path / 'output' / 'raw_data')),
            patch.object(scanner_mod.Config, 'REPORTS_DIR', str(tmp_path / 'output' / 'reports')),
            patch.object(scanner_mod.Config, 'LOGS_DIR', str(tmp_path / 'output' / 'logs')),
            patch('scanner.shodan.Shodan'),
        ]
        for p in self._patchers:
            p.start()

        scanner_obj = scanner_mod.BitcoinNodeScanner(api_key='test_api_key')
        mock_shodan = scanner_mod.shodan.Shodan
        return scanner_obj, mock_shodan

    def teardown_method(self):
        for p in getattr(self, '_patchers', []):
            p.stop()
        self._patchers = []

    def test_init_raises_without_api_key(self):
        from scanner import BitcoinNodeScanner
        with pytest.raises(ValueError, match="Please set SHODAN_API_KEY"):
            BitcoinNodeScanner(api_key='YOUR_API_KEY_HERE')

    def test_init_raises_none_api_key(self):
        from scanner import BitcoinNodeScanner
        with patch('scanner.Config.SHODAN_API_KEY', 'YOUR_API_KEY_HERE'):
            with pytest.raises(ValueError, match="Please set SHODAN_API_KEY"):
                BitcoinNodeScanner()

    def test_init_creates_directories(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert os.path.isdir(str(tmp_path / 'output'))
        assert os.path.isdir(str(tmp_path / 'output' / 'raw_data'))
        assert os.path.isdir(str(tmp_path / 'output' / 'reports'))
        assert os.path.isdir(str(tmp_path / 'output' / 'logs'))

    def test_init_sets_attributes(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert scanner.api_key == 'test_api_key'
        assert scanner.results == []
        assert scanner.unique_ips == set()
        assert scanner.timestamp is not None

    def test_log_writes_to_file(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.log("Test message", "INFO")
        with open(scanner.log_file, 'r') as f:
            content = f.read()
        assert "Test message" in content
        assert "[INFO]" in content

    def test_log_with_error_level(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.log("Error occurred", "ERROR")
        with open(scanner.log_file, 'r') as f:
            content = f.read()
        assert "[ERROR]" in content

    # --- get_account_info ---

    def test_get_account_info_success(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.api.info.return_value = {'query_credits': 100, 'scan_credits': 50}
        info = scanner.get_account_info()
        assert info['query_credits'] == 100
        assert info['scan_credits'] == 50

    def test_get_account_info_error(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.api.info.side_effect = Exception("API Error")
        info = scanner.get_account_info()
        assert info is None

    # --- extract_ssl_info ---

    def test_extract_ssl_info_with_ssl(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {
            'ssl': {
                'version': 'TLSv1.2',
                'cipher': {'name': 'AES256-SHA'},
                'cert': {
                    'issued': '2024-01-01',
                    'expires': '2025-01-01',
                    'subject': {'CN': 'test.com'},
                },
            }
        }
        ssl_info = scanner.extract_ssl_info(result)
        assert ssl_info['enabled'] is True
        assert ssl_info['version'] == 'TLSv1.2'
        assert ssl_info['cipher'] == 'AES256-SHA'

    def test_extract_ssl_info_without_ssl(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {}
        ssl_info = scanner.extract_ssl_info(result)
        assert ssl_info == {}

    # --- parse_node_data ---

    def test_parse_node_data(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {
            'ip_str': '1.2.3.4',
            'port': 8333,
            'transport': 'tcp',
            'product': 'Bitcoin Core',
            'version': '0.21.0',
            'data': '/Satoshi:0.21.0/',
            'org': 'Test Org',
            'isp': 'Test ISP',
            'asn': 'AS12345',
            'location': {
                'country_name': 'Germany',
                'country_code': 'DE',
                'city': 'Berlin',
            },
            'hostnames': ['test.com'],
            'domains': ['test.com'],
            'timestamp': '2024-01-01',
            'vulns': [],
            'cpe': [],
        }
        node = scanner.parse_node_data(result, 'Bitcoin')
        assert node['ip'] == '1.2.3.4'
        assert node['port'] == 8333
        assert node['product'] == 'Bitcoin Core'
        assert node['country'] == 'Germany'
        assert node['country_code'] == 'DE'
        assert node['query'] == 'Bitcoin'

    def test_parse_node_data_missing_fields(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'ip_str': '5.6.7.8', 'port': 8333}
        node = scanner.parse_node_data(result, 'test')
        assert node['ip'] == '5.6.7.8'
        assert node['product'] == ''
        assert node['version'] == ''
        assert node['country'] == ''

    # --- is_vulnerable_version ---

    def test_is_vulnerable_known_version(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert scanner.is_vulnerable_version('0.15.0') is True
        assert scanner.is_vulnerable_version('0.16.0') is True
        assert scanner.is_vulnerable_version('0.21.0') is True

    def test_is_not_vulnerable_version(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert scanner.is_vulnerable_version('25.0') is False
        assert scanner.is_vulnerable_version('27.0') is False

    def test_is_vulnerable_satoshi_old(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert scanner.is_vulnerable_version('Satoshi:0.18.0') is True

    def test_is_vulnerable_satoshi_new(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert scanner.is_vulnerable_version('Satoshi:0.22.0') is False

    def test_is_vulnerable_invalid_format(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        assert scanner.is_vulnerable_version('') is False
        assert scanner.is_vulnerable_version('unknown') is False

    # --- analyze_risk_level ---

    def test_risk_critical_rpc_port(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8332, 'version': '25.0'}
        assert scanner.analyze_risk_level(result) == 'CRITICAL'

    def test_risk_high_multiple_factors(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {
            'port': 8333,
            'version': '0.15.0.99.dev',
        }
        assert scanner.analyze_risk_level(result) == 'HIGH'

    def test_risk_medium_one_factor(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8333, 'version': '0.15.0'}
        assert scanner.analyze_risk_level(result) == 'MEDIUM'

    def test_risk_low_no_factors(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8333, 'version': '25.0'}
        assert scanner.analyze_risk_level(result) == 'LOW'

    def test_risk_high_multiple_services(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {
            'port': 8333,
            'version': '0.15.0',
            'enrichment': {
                'all_ports': [22, 80, 443, 3306],
            },
        }
        assert scanner.analyze_risk_level(result) == 'HIGH'

    # --- extract_version_from_banner ---

    def test_extract_version_satoshi_banner(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'banner': '/Satoshi:0.21.0/', 'product': '', 'version': ''}
        version = scanner.extract_version_from_banner(result)
        assert version == 'Satoshi:0.21.0'

    def test_extract_version_product_version(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'banner': '', 'product': 'Bitcoin Core', 'version': '25.0'}
        version = scanner.extract_version_from_banner(result)
        assert version == 'Bitcoin Core:25.0'

    def test_extract_version_only_version(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'banner': '', 'product': '', 'version': '25.0'}
        version = scanner.extract_version_from_banner(result)
        assert version == '25.0'

    def test_extract_version_unknown(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'banner': '', 'product': '', 'version': ''}
        version = scanner.extract_version_from_banner(result)
        assert version == 'Unknown'

    # --- get_risk_reason ---

    def test_risk_reason_rpc(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8332, 'version': '25.0'}
        reason = scanner.get_risk_reason(result, 'CRITICAL')
        assert 'RPC_EXPOSED' in reason

    def test_risk_reason_vulnerable(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8333, 'version': '0.15.0'}
        reason = scanner.get_risk_reason(result, 'MEDIUM')
        assert 'VULNERABLE_VERSION' in reason

    def test_risk_reason_dev_version(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8333, 'version': '0.99.0'}
        reason = scanner.get_risk_reason(result, 'MEDIUM')
        assert 'DEV_VERSION' in reason

    def test_risk_reason_multiple_services(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {
            'port': 8333,
            'version': '25.0',
            'enrichment': {'all_ports': [22, 80, 443, 3306]},
        }
        reason = scanner.get_risk_reason(result, 'HIGH')
        assert 'MULTIPLE_SERVICES' in reason

    def test_risk_reason_unknown(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        result = {'port': 8333, 'version': '25.0'}
        reason = scanner.get_risk_reason(result, 'LOW')
        assert reason == 'UNKNOWN'

    # --- search_bitcoin_nodes ---

    def test_search_bitcoin_nodes(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.api.search.return_value = {
            'total': 1,
            'matches': [{
                'ip_str': '1.2.3.4',
                'port': 8333,
                'product': 'Bitcoin',
                'version': '25.0',
                'data': '',
                'org': 'Org',
                'isp': 'ISP',
                'asn': 'AS1',
                'location': {'country_name': 'US', 'country_code': 'US', 'city': 'NY'},
                'hostnames': [],
                'domains': [],
                'timestamp': '',
                'vulns': [],
                'cpe': [],
            }],
        }
        results = scanner.search_bitcoin_nodes('Bitcoin', max_results=10)
        assert len(results) == 1
        assert results[0]['ip'] == '1.2.3.4'
        assert '1.2.3.4' in scanner.unique_ips

    def test_search_bitcoin_nodes_api_error(self, tmp_path):
        import shodan
        scanner, _ = self._make_scanner(tmp_path)
        scanner.api.search.side_effect = shodan.APIError('API error')
        results = scanner.search_bitcoin_nodes('Bitcoin')
        assert results == []

    def test_search_bitcoin_nodes_upgrade_error(self, tmp_path):
        import shodan
        scanner, _ = self._make_scanner(tmp_path)
        # First call succeeds, pagination triggers upgrade error
        scanner.api.search.side_effect = [
            {'total': 200, 'matches': [
                {'ip_str': f'1.2.3.{i}', 'port': 8333, 'product': '', 'version': '',
                 'data': '', 'org': '', 'isp': '', 'asn': '', 'location': {},
                 'hostnames': [], 'domains': [], 'timestamp': '', 'vulns': [], 'cpe': []}
                for i in range(100)
            ]},
            shodan.APIError('Upgrade your API plan'),
        ]
        results = scanner.search_bitcoin_nodes('Bitcoin', max_results=200)
        assert len(results) == 100

    # --- enrich_with_host_scan ---

    def test_enrich_with_host_scan_success(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.api.host.return_value = {
            'data': [
                {'port': 8333, 'product': 'Bitcoin', 'version': '25.0'},
                {'port': 22, 'product': 'OpenSSH', 'version': '8.0'},
            ],
            'tags': ['bitcoin'],
            'vulns': ['CVE-2021-1234'],
            'os': 'Linux',
            'last_update': '2024-01-01',
        }
        result = scanner.enrich_with_host_scan('1.2.3.4')
        assert result['all_ports'] == [8333, 22]
        assert result['os'] == 'Linux'
        assert 'CVE-2021-1234' in result['vulns']

    def test_enrich_with_host_scan_error(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.api.host.side_effect = Exception("Host error")
        result = scanner.enrich_with_host_scan('1.2.3.4')
        assert result == {}

    # --- generate_statistics ---

    def test_generate_statistics(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.unique_ips = {'1.2.3.4', '5.6.7.8'}
        scanner.results = [
            {'port': 8333, 'country_code': 'US', 'banner': '/Satoshi:25.0/',
             'product': '', 'version': '25.0', 'asn': 'AS1'},
            {'port': 8332, 'country_code': 'DE', 'banner': '',
             'product': 'Bitcoin', 'version': '0.15.0', 'asn': 'AS2'},
        ]
        stats = scanner.generate_statistics()
        assert stats['total_results'] == 2
        assert stats['unique_ips'] == 2
        assert stats['rpc_exposed'] == 1
        assert stats['vulnerable_nodes'] == 1
        assert 8333 in stats['port_distribution']
        assert 8332 in stats['port_distribution']

    def test_generate_statistics_empty(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        stats = scanner.generate_statistics()
        assert stats['total_results'] == 0
        assert stats['unique_ips'] == 0

    # --- save_raw_data ---

    def test_save_raw_data_json(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.results = [{'ip': '1.2.3.4', 'port': 8333}]
        scanner.save_raw_data()

        raw_dir = tmp_path / 'output' / 'raw_data'
        json_files = list(raw_dir.glob('nodes_*.json'))
        assert len(json_files) == 1
        with open(json_files[0]) as f:
            data = json.load(f)
        assert data[0]['ip'] == '1.2.3.4'

    def test_save_raw_data_csv(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.results = [{'ip': '1.2.3.4', 'port': 8333, 'hostnames': ['test.com']}]
        scanner.save_raw_data()

        raw_dir = tmp_path / 'output' / 'raw_data'
        csv_files = list(raw_dir.glob('nodes_*.csv'))
        assert len(csv_files) == 1

    def test_save_raw_data_empty(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.results = []
        scanner.save_raw_data()
        # Should still create JSON file
        raw_dir = tmp_path / 'output' / 'raw_data'
        json_files = list(raw_dir.glob('nodes_*.json'))
        assert len(json_files) == 1

    # --- generate_report ---

    def test_generate_report(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        stats = {
            'total_results': 2,
            'unique_ips': 2,
            'vulnerable_nodes': 1,
            'rpc_exposed': 1,
            'risk_distribution': {'CRITICAL': 1, 'LOW': 1},
            'port_distribution': {8333: 1, 8332: 1},
            'version_distribution': {'Satoshi:25.0': 1},
            'country_distribution': {'US': 1, 'DE': 1},
            'asn_distribution': {'AS1': 1},
        }
        scanner.generate_report(stats)
        reports_dir = tmp_path / 'output' / 'reports'
        report_files = list(reports_dir.glob('report_*.txt'))
        assert len(report_files) == 1
        with open(report_files[0]) as f:
            content = f.read()
        assert 'BITCOIN NODE SECURITY SCAN REPORT' in content
        assert 'EXECUTIVE SUMMARY' in content

    # --- generate_critical_nodes_list ---

    def test_generate_critical_nodes_list(self, tmp_path):
        scanner, _ = self._make_scanner(tmp_path)
        scanner.results = [
            {'ip': '1.2.3.4', 'port': 8332, 'version': '25.0',
             'banner': '', 'product': '', 'country_code': 'US',
             'organization': 'Org', 'asn': 'AS1'},
            {'ip': '5.6.7.8', 'port': 8333, 'version': '25.0',
             'banner': '', 'product': '', 'country_code': 'DE',
             'organization': 'Org2', 'asn': 'AS2'},
        ]
        critical = scanner.generate_critical_nodes_list()
        assert len(critical) == 1
        assert critical[0]['ip'] == '1.2.3.4'
        assert critical[0]['risk_level'] == 'CRITICAL'


# ============================================================================
# CachedNodeManager Tests
# ============================================================================

class TestCachedNodeManager:
    """Test CachedNodeManager class"""

    def test_init_empty_cache(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)
        assert manager.cache == {}

    def test_update_and_get_cached(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)

        nodes = [{'ip': '1.2.3.4', 'port': 8333}]
        manager.update_cache(nodes)

        cached = manager.get_cached('1.2.3.4')
        assert cached is not None
        assert cached['ip'] == '1.2.3.4'

    def test_is_cached_fresh(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)

        manager.update_cache([{'ip': '1.2.3.4', 'port': 8333}])
        assert manager.is_cached('1.2.3.4') is True

    def test_is_cached_stale(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)

        old_timestamp = (datetime.now() - timedelta(days=10)).isoformat()
        manager.cache['1.2.3.4'] = {
            'timestamp': old_timestamp,
            'data': {'ip': '1.2.3.4'},
        }
        assert manager.is_cached('1.2.3.4') is False

    def test_is_cached_not_found(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)
        assert manager.is_cached('9.9.9.9') is False

    def test_filter_uncached(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)

        manager.update_cache([{'ip': '1.2.3.4', 'port': 8333}])
        nodes = [
            {'ip': '1.2.3.4', 'port': 8333},
            {'ip': '5.6.7.8', 'port': 8333},
        ]
        uncached = manager.filter_uncached(nodes)
        assert len(uncached) == 1
        assert uncached[0]['ip'] == '5.6.7.8'

    def test_get_stats(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)

        manager.update_cache([{'ip': '1.2.3.4'}, {'ip': '5.6.7.8'}])
        stats = manager.get_stats()
        assert stats['total_cached'] == 2
        assert stats['fresh'] == 2
        assert stats['stale'] == 0

    def test_save_and_reload_cache(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        manager = CachedNodeManager(cache_file=cache_file)
        manager.update_cache([{'ip': '1.2.3.4', 'port': 8333}])

        # Reload from file
        manager2 = CachedNodeManager(cache_file=cache_file)
        assert manager2.is_cached('1.2.3.4') is True

    def test_load_corrupted_cache(self, tmp_path):
        from scanner import CachedNodeManager
        cache_file = str(tmp_path / 'cache' / 'test_cache.json')
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        with open(cache_file, 'w') as f:
            f.write('not valid json')
        manager = CachedNodeManager(cache_file=cache_file)
        assert manager.cache == {}


# ============================================================================
# OptimizedConfig Tests
# ============================================================================

class TestOptimizedConfig:
    """Test OptimizedConfig class"""

    def test_optimized_queries(self):
        from scanner import OptimizedConfig
        assert isinstance(OptimizedConfig.QUERIES_OPTIMIZED, list)
        assert len(OptimizedConfig.QUERIES_OPTIMIZED) > 0

    def test_max_results_critical_higher(self):
        from scanner import OptimizedConfig
        assert OptimizedConfig.MAX_RESULTS_CRITICAL > OptimizedConfig.MAX_RESULTS_NORMAL

    def test_cache_settings(self):
        from scanner import OptimizedConfig
        assert OptimizedConfig.CACHE_MAX_AGE_DAYS > 0
        assert OptimizedConfig.MAX_ENRICHMENTS > 0


# ============================================================================
# OptimizedBitcoinScanner Tests
# ============================================================================

class TestOptimizedBitcoinScanner:
    """Test OptimizedBitcoinScanner class"""

    def _make_optimized_scanner(self, tmp_path, use_cache=False):
        """Helper to create an optimized scanner with mocked API"""
        import scanner as scanner_mod

        self._patchers = [
            patch.object(scanner_mod.Config, 'OUTPUT_DIR', str(tmp_path / 'output')),
            patch.object(scanner_mod.Config, 'RAW_DATA_DIR', str(tmp_path / 'output' / 'raw_data')),
            patch.object(scanner_mod.Config, 'REPORTS_DIR', str(tmp_path / 'output' / 'reports')),
            patch.object(scanner_mod.Config, 'LOGS_DIR', str(tmp_path / 'output' / 'logs')),
            patch.object(scanner_mod.OptimizedConfig, 'CACHE_FILE', str(tmp_path / 'cache' / 'cache.json')),
            patch('scanner.shodan.Shodan'),
        ]
        for p in self._patchers:
            p.start()

        scanner_obj = scanner_mod.OptimizedBitcoinScanner(
            api_key='test_api_key', use_cache=use_cache
        )
        mock_shodan = scanner_mod.shodan.Shodan
        return scanner_obj, mock_shodan

    def teardown_method(self):
        for p in getattr(self, '_patchers', []):
            p.stop()
        self._patchers = []

    def test_init_with_cache(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path, use_cache=True)
        assert scanner.use_cache is True
        assert scanner.cache_manager is not None

    def test_init_without_cache(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path, use_cache=False)
        assert scanner.use_cache is False
        assert scanner.cache_manager is None

    def test_credit_usage_init(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path)
        assert scanner.credit_usage['query_credits_used'] == 0
        assert scanner.credit_usage['scan_credits_used'] == 0
        assert scanner.credit_usage['nodes_from_cache'] == 0
        assert scanner.credit_usage['nodes_scanned'] == 0

    def test_smart_search_critical(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path)
        scanner.api.search.return_value = {'total': 0, 'matches': []}
        scanner.smart_search('port:8332', is_critical=True)
        assert scanner.credit_usage['query_credits_used'] == 1

    def test_smart_search_normal(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path)
        scanner.api.search.return_value = {'total': 0, 'matches': []}
        scanner.smart_search('Bitcoin', is_critical=False)
        assert scanner.credit_usage['query_credits_used'] == 1

    def test_deduplicate_by_ip(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path)
        results = [
            {'ip': '1.2.3.4', 'port': 8333},
            {'ip': '1.2.3.4', 'port': 8332},
            {'ip': '5.6.7.8', 'port': 8333},
        ]
        unique = scanner._deduplicate_by_ip(results)
        assert len(unique) == 2
        ips = [r['ip'] for r in unique]
        assert '1.2.3.4' in ips
        assert '5.6.7.8' in ips

    def test_enrich_critical_only(self, tmp_path):
        scanner, _ = self._make_optimized_scanner(tmp_path)
        scanner.api.host.return_value = {
            'data': [], 'tags': [], 'vulns': [],
            'os': 'Linux', 'last_update': '',
        }
        results = [
            {'ip': '1.2.3.4', 'port': 8332, 'version': '25.0'},
            {'ip': '5.6.7.8', 'port': 8333, 'version': '25.0'},
        ]
        scanner.enrich_critical_only(results, max_enrichments=10)
        assert scanner.credit_usage['scan_credits_used'] == 1
        assert 'enrichment' in results[0]
        assert 'enrichment' not in results[1]
