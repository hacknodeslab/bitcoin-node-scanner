#!/usr/bin/env python3
"""
Test suite for utility functions
"""

import pytest
import tempfile
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, mock_open

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils import (
    validate_ip_address,
    validate_port,
    parse_version_number,
    compare_versions,
    sanitize_filename,
    ensure_directory,
    format_bytes,
    format_timestamp,
    truncate_string,
    parse_banner_fields,
    deduplicate_list,
    merge_dictionaries,
    safe_divide,
    calculate_percentage,
    batch_list,
    extract_asn_number,
    is_private_ip,
    ProgressTracker
)


class TestValidation:
    """Test validation functions"""
    
    def test_validate_ip_address_ipv4(self):
        """Test IPv4 address validation"""
        assert validate_ip_address("192.168.1.1") == True
        assert validate_ip_address("8.8.8.8") == True
        assert validate_ip_address("0.0.0.0") == True
        assert validate_ip_address("255.255.255.255") == True
        
        # Invalid IPv4
        assert validate_ip_address("256.1.1.1") == False
        assert validate_ip_address("192.168.1") == False
        assert validate_ip_address("192.168.1.1.1") == False
        assert validate_ip_address("192.168.1.-1") == False
    
    def test_validate_ip_address_invalid(self):
        """Test invalid IP address formats"""
        assert validate_ip_address("not.an.ip") == False
        assert validate_ip_address("") == False
        assert validate_ip_address("192.168.1.256") == False
        assert validate_ip_address("abc.def.ghi.jkl") == False
    
    def test_validate_port(self):
        """Test port validation"""
        assert validate_port(80) == True
        assert validate_port(8333) == True
        assert validate_port(1) == True
        assert validate_port(65535) == True
        
        # Invalid ports
        assert validate_port(0) == False
        assert validate_port(65536) == False
        assert validate_port(-1) == False
        assert validate_port("80") == False
        assert validate_port(None) == False


class TestVersionParsing:
    """Test version parsing functions"""
    
    def test_parse_version_number(self):
        """Test version number parsing"""
        assert parse_version_number("1.2.3") == (1, 2, 3)
        assert parse_version_number("0.21.1") == (0, 21, 1)
        assert parse_version_number("Satoshi:0.21.1") == (0, 21, 1)
        assert parse_version_number("invalid") == None
        assert parse_version_number("") == None
        assert parse_version_number("a" * 200) == None  # Too long
    
    def test_compare_versions(self):
        """Test version comparison"""
        assert compare_versions("1.2.3", "1.2.4") == -1
        assert compare_versions("1.2.4", "1.2.3") == 1
        assert compare_versions("1.2.3", "1.2.3") == 0
        assert compare_versions("invalid", "1.2.3") == None


class TestStringUtils:
    """Test string utility functions"""
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        assert sanitize_filename("normal_file.txt") == "normal_file.txt"
        assert sanitize_filename("file:with<invalid>chars.txt") == "file_with_invalid_chars.txt"
        assert sanitize_filename("  ..spaced..  ") == "spaced"
    
    def test_truncate_string(self):
        """Test string truncation"""
        assert truncate_string("short", 10) == "short"
        assert truncate_string("very long string", 10, "...") == "very lo..."
        assert truncate_string("exactly10c", 10) == "exactly10c"
    
    def test_parse_banner_fields(self):
        """Test banner field parsing"""
        banner = "/Satoshi:0.21.1/Bitcoin Knots:v0.21.1/protocol version 70001"
        fields = parse_banner_fields(banner)
        
        assert "satoshi_version" in fields
        assert fields["satoshi_version"] == "0.21.1"
        assert fields["protocol_version"] == "70001"


class TestFileUtils:
    """Test file utility functions"""
    
    def test_ensure_directory(self):
        """Test directory creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = os.path.join(tmpdir, "new_dir", "nested")
            ensure_directory(test_dir)
            assert os.path.exists(test_dir)
    
    def test_format_bytes(self):
        """Test byte formatting"""
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1048576) == "1.00 MB"
        assert format_bytes(500) == "500.00 B"


class TestDataProcessing:
    """Test data processing functions"""
    
    def test_deduplicate_list(self):
        """Test list deduplication"""
        items = [1, 2, 2, 3, 1, 4]
        unique = deduplicate_list(items)
        assert unique == [1, 2, 3, 4]
        
        # With key function
        items = [{'id': 1}, {'id': 2}, {'id': 1}]
        unique = deduplicate_list(items, key_func=lambda x: x['id'])
        assert len(unique) == 2
        assert unique[0]['id'] == 1
        assert unique[1]['id'] == 2
    
    def test_merge_dictionaries(self):
        """Test dictionary merging"""
        dict1 = {'a': 1, 'b': 2}
        dict2 = {'b': 3, 'c': 4}
        merged = merge_dictionaries(dict1, dict2)
        
        assert merged == {'a': 1, 'b': 3, 'c': 4}
    
    def test_safe_divide(self):
        """Test safe division"""
        assert safe_divide(10, 2) == 5.0
        assert safe_divide(10, 0) == 0.0
        assert safe_divide(10, 0, default=1.0) == 1.0
        assert safe_divide("invalid", 2) == 0.0
    
    def test_calculate_percentage(self):
        """Test percentage calculation"""
        assert calculate_percentage(50, 100) == 50.0
        assert calculate_percentage(1, 3, 2) == 33.33
        assert calculate_percentage(10, 0) == 0.0
    
    def test_batch_list(self):
        """Test list batching"""
        items = [1, 2, 3, 4, 5, 6, 7]
        batches = batch_list(items, 3)
        
        assert len(batches) == 3
        assert batches[0] == [1, 2, 3]
        assert batches[1] == [4, 5, 6]
        assert batches[2] == [7]


class TestNetworkUtils:
    """Test network utility functions"""
    
    def test_extract_asn_number(self):
        """Test ASN extraction"""
        assert extract_asn_number("AS1234") == 1234
        assert extract_asn_number("1234") == 1234
        assert extract_asn_number("invalid") == 0
    
    def test_is_private_ip(self):
        """Test private IP detection"""
        assert is_private_ip("192.168.1.1") == True
        assert is_private_ip("10.0.0.1") == True
        assert is_private_ip("172.16.0.1") == True
        assert is_private_ip("127.0.0.1") == True
        
        assert is_private_ip("8.8.8.8") == False
        assert is_private_ip("1.1.1.1") == False


class TestTimestampUtils:
    """Test timestamp utility functions"""
    
    def test_format_timestamp(self):
        """Test timestamp formatting"""
        # Test string timestamps
        result = format_timestamp("2023-01-01 12:00:00")
        assert result == "2023-01-01 12:00:00"
        
        # Test Unix timestamp
        result = format_timestamp(1672574400)  # 2023-01-01 12:00:00 UTC
        assert "2023-01-01" in result
        
        # Test datetime object
        dt = datetime(2023, 1, 1, 12, 0, 0)
        result = format_timestamp(dt)
        assert result == "2023-01-01 12:00:00"


class TestProgressTracker:
    """Test progress tracker"""
    
    def test_progress_tracker_initialization(self):
        """Test progress tracker initialization"""
        tracker = ProgressTracker(100, "Testing")
        assert tracker.total == 100
        assert tracker.current == 0
        assert tracker.description == "Testing"
    
    @patch('builtins.print')
    def test_progress_tracker_update(self, mock_print):
        """Test progress tracker update"""
        tracker = ProgressTracker(10, "Testing")
        tracker.update(5)
        
        assert tracker.current == 5
        mock_print.assert_called()
    
    @patch('builtins.print')
    def test_progress_tracker_finish(self, mock_print):
        """Test progress tracker finish"""
        tracker = ProgressTracker(10, "Testing")
        tracker.finish()
        
        assert tracker.current == 10
        mock_print.assert_called()


class TestRateLimitDecorator:
    """Test rate limit decorator"""
    
    @patch('utils.time.sleep')
    @patch('utils.time.time')
    def test_rate_limit_decorator(self, mock_time, mock_sleep):
        """Test rate limiting decorator"""
        from utils import rate_limit
        
        # Mock time to control timing - need more values for multiple calls
        mock_time.side_effect = [0, 0, 0.5, 1.5, 1.5]  # More time values for all calls
        
        @rate_limit(delay=1.0)
        def test_function():
            return "called"
        
        # First call - no delay
        result1 = test_function()
        assert result1 == "called"
        
        # Second call - should trigger delay
        result2 = test_function()
        assert result2 == "called"
        mock_sleep.assert_called_with(0.5)  # 1.0 - 0.5 = 0.5


if __name__ == "__main__":
    pytest.main([__file__])