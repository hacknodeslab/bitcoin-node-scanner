#!/usr/bin/env python3
"""
Test suite for credit tracker functionality
"""

import pytest
import tempfile
import os
import json
from datetime import datetime, timedelta
from unittest.mock import patch, mock_open, MagicMock

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from credit_tracker import CreditTracker


class TestCreditTracker:
    """Test credit tracking functionality"""
    
    def setup_method(self):
        """Setup for each test"""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.temp_file.close()
        self.tracker = CreditTracker(log_file=self.temp_file.name)
    
    def teardown_method(self):
        """Cleanup after each test"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_initialization_empty(self):
        """Test tracker initialization with empty log"""
        assert self.tracker.history == []
        assert self.tracker.log_file == self.temp_file.name
    
    def test_log_usage(self):
        """Test logging credit usage"""
        self.tracker.log_usage(
            query_credits=5,
            scan_credits=10,
            scan_type='quick',
            notes='Test scan'
        )
        
        assert len(self.tracker.history) == 1
        entry = self.tracker.history[0]
        
        assert entry['query_credits_used'] == 5
        assert entry['scan_credits_used'] == 10
        assert entry['scan_type'] == 'quick'
        assert entry['notes'] == 'Test scan'
        assert 'timestamp' in entry
    
    def test_save_and_load_history(self):
        """Test saving and loading history"""
        # Add some entries
        self.tracker.log_usage(5, 10, 'quick', 'Test 1')
        self.tracker.log_usage(3, 5, 'medium', 'Test 2')
        
        # Create new tracker with same file
        new_tracker = CreditTracker(log_file=self.temp_file.name)
        
        assert len(new_tracker.history) == 2
        assert new_tracker.history[0]['notes'] == 'Test 1'
        assert new_tracker.history[1]['notes'] == 'Test 2'
    
    def test_get_monthly_usage_current_month(self):
        """Test getting current month usage"""
        now = datetime.now()
        
        # Add entries for current month
        self.tracker.log_usage(5, 10, 'quick', 'Current month 1')
        self.tracker.log_usage(3, 7, 'medium', 'Current month 2')
        
        monthly = self.tracker.get_monthly_usage()
        
        assert monthly['year'] == now.year
        assert monthly['month'] == now.month
        assert monthly['total_scans'] == 2
        assert monthly['query_credits_used'] == 8
        assert monthly['scan_credits_used'] == 17
        assert 'quick' in monthly['scan_type_breakdown']
        assert 'medium' in monthly['scan_type_breakdown']
    
    def test_get_monthly_usage_specific_month(self):
        """Test getting usage for specific month"""
        # Add some current entries
        self.tracker.log_usage(5, 10, 'quick', 'Current')
        
        # Mock old entries by modifying timestamps
        old_timestamp = datetime(2023, 6, 15).isoformat()
        self.tracker.history.append({
            'timestamp': old_timestamp,
            'query_credits_used': 2,
            'scan_credits_used': 4,
            'scan_type': 'old',
            'notes': 'Old entry'
        })
        self.tracker.save_history()
        
        monthly = self.tracker.get_monthly_usage(year=2023, month=6)
        
        assert monthly['year'] == 2023
        assert monthly['month'] == 6
        assert monthly['total_scans'] == 1
        assert monthly['query_credits_used'] == 2
        assert monthly['scan_credits_used'] == 4
    
    def test_project_monthly_usage(self):
        """Test monthly usage projection"""
        # Mock datetime.now() to control the "current" day
        with patch('credit_tracker.datetime') as mock_datetime:
            mock_now = datetime(2023, 6, 15)  # 15th day of month
            mock_datetime.now.return_value = mock_now
            mock_datetime.fromisoformat = datetime.fromisoformat
            
            # Add some usage for "this month"
            self.tracker.history = [
                {
                    'timestamp': datetime(2023, 6, 5).isoformat(),
                    'query_credits_used': 10,
                    'scan_credits_used': 20,
                    'scan_type': 'medium',
                    'notes': 'Test'
                },
                {
                    'timestamp': datetime(2023, 6, 10).isoformat(),
                    'query_credits_used': 5,
                    'scan_credits_used': 15,
                    'scan_type': 'quick',
                    'notes': 'Test 2'
                }
            ]
            
            projection = self.tracker.project_monthly_usage(
                plan_limit=100,
                current_query_credits=85,
                current_scan_credits=65
            )
            
            assert projection['current_usage']['query_credits_used'] == 15
            assert projection['current_usage']['scan_credits_used'] == 35
            assert projection['days_elapsed'] == 15
            assert projection['days_remaining'] == 15
            
            # Check projections
            assert projection['query_credits']['used'] == 15
            assert projection['query_credits']['remaining'] == 85
            assert projection['query_credits']['api_current'] == 85
            
            assert projection['scan_credits']['used'] == 35
            assert projection['scan_credits']['remaining'] == 65
            assert projection['scan_credits']['api_current'] == 65
    
    def test_project_monthly_usage_no_api_data(self):
        """Test projection without real-time API data"""
        projection = self.tracker.project_monthly_usage(plan_limit=100)
        
        assert projection['query_credits']['api_current'] is None
        assert projection['scan_credits']['api_current'] is None
        assert projection['query_credits']['limit'] == 100
        assert projection['scan_credits']['limit'] == 100
    
    def test_get_recommendations_high_usage(self):
        """Test recommendations for high usage"""
        # Mock projection with high usage
        projection = {
            'query_credits': {
                'projected_eom': 120,
                'limit': 100
            },
            'scan_credits': {
                'projected_eom': 85,
                'limit': 100
            }
        }
        
        recommendations = self.tracker.get_recommendations(projection)
        
        assert any("WARNING" in rec for rec in recommendations)
        assert any("exceed query credit limit" in rec for rec in recommendations)
        assert any("reducing scan frequency" in rec for rec in recommendations)
    
    def test_get_recommendations_good_usage(self):
        """Test recommendations for good usage"""
        projection = {
            'query_credits': {
                'projected_eom': 40,
                'limit': 100
            },
            'scan_credits': {
                'projected_eom': 30,
                'limit': 100
            }
        }
        
        recommendations = self.tracker.get_recommendations(projection)
        
        assert any("Good query credit usage" in rec for rec in recommendations)
        assert any("Good scan credit usage" in rec for rec in recommendations)
        assert any("increase scan frequency" in rec for rec in recommendations)
    
    def test_get_recommendations_high_query_usage(self):
        """Test recommendations when query usage is high but not exceeded"""
        projection = {
            'query_credits': {
                'projected_eom': 90,
                'limit': 100
            },
            'scan_credits': {
                'projected_eom': 40,
                'limit': 100
            }
        }
        
        recommendations = self.tracker.get_recommendations(projection)
        
        assert any("High query credit usage" in rec for rec in recommendations)
        assert any("Monitor usage closely" in rec for rec in recommendations)
    
    def test_get_recommendations_scan_exceeded(self):
        """Test recommendations when scan credits exceed limit"""
        projection = {
            'query_credits': {
                'projected_eom': 40,
                'limit': 100
            },
            'scan_credits': {
                'projected_eom': 120,
                'limit': 100
            }
        }
        
        recommendations = self.tracker.get_recommendations(projection)
        
        assert any("exceed scan credit limit" in rec for rec in recommendations)
        assert any("Reduce enrichment scope" in rec for rec in recommendations)
    
    def test_get_recommendations_high_scan_usage(self):
        """Test recommendations when scan usage is high but not exceeded"""
        projection = {
            'query_credits': {
                'projected_eom': 40,
                'limit': 100
            },
            'scan_credits': {
                'projected_eom': 85,
                'limit': 100
            }
        }
        
        recommendations = self.tracker.get_recommendations(projection)
        
        assert any("High scan credit usage" in rec for rec in recommendations)
        assert any("Limit enrichment to critical nodes only" in rec for rec in recommendations)
    
    @patch('builtins.print')
    def test_print_report(self, mock_print):
        """Test report printing"""
        # Add some usage
        self.tracker.log_usage(10, 20, 'medium', 'Test')
        
        self.tracker.print_report()
        
        # Verify that print was called (report was generated)
        mock_print.assert_called()
        
        # Check that report contains expected sections
        all_calls = [str(call) for call in mock_print.call_args_list]
        report_text = ' '.join(all_calls)
        
        assert "SHODAN CREDIT USAGE REPORT" in report_text
        assert "QUERY CREDITS" in report_text
        assert "SCAN CREDITS" in report_text
    
    @patch('builtins.print')
    def test_print_report_with_api_credits(self, mock_print):
        """Test report printing with real API credit values"""
        self.tracker.log_usage(10, 20, 'medium', 'Test')
        
        projection = self.tracker.project_monthly_usage(
            plan_limit=100,
            current_query_credits=85,
            current_scan_credits=65
        )
        self.tracker.print_report(projection)
        
        all_calls = [str(call) for call in mock_print.call_args_list]
        report_text = ' '.join(all_calls)
        
        assert "Remaining (API)" in report_text
    
    @patch('builtins.print')
    def test_print_report_without_api_credits(self, mock_print):
        """Test report printing without API credit values"""
        self.tracker.log_usage(10, 20, 'medium', 'Test')
        
        projection = self.tracker.project_monthly_usage(plan_limit=100)
        self.tracker.print_report(projection)
        
        all_calls = [str(call) for call in mock_print.call_args_list]
        report_text = ' '.join(all_calls)
        
        assert "Remaining:" in report_text
    
    @patch('builtins.print')
    def test_print_report_with_scan_type_breakdown(self, mock_print):
        """Test report printing includes scan type breakdown"""
        self.tracker.log_usage(5, 10, 'quick', 'Test 1')
        self.tracker.log_usage(10, 25, 'full', 'Test 2')
        
        self.tracker.print_report()
        
        all_calls = [str(call) for call in mock_print.call_args_list]
        report_text = ' '.join(all_calls)
        
        assert "SCAN TYPE BREAKDOWN" in report_text
    
    def test_load_invalid_json(self):
        """Test loading invalid JSON file"""
        # Write invalid JSON
        with open(self.temp_file.name, 'w') as f:
            f.write("invalid json content")
        
        # Should handle gracefully and return empty history
        tracker = CreditTracker(log_file=self.temp_file.name)
        assert tracker.history == []
    
    def test_load_nonexistent_file(self):
        """Test loading non-existent file"""
        nonexistent_file = "/tmp/nonexistent_credit_log.json"
        tracker = CreditTracker(log_file=nonexistent_file)
        assert tracker.history == []
    
    def test_ensure_log_dir(self):
        """Test log directory creation"""
        nested_path = os.path.join(self.temp_file.name + "_dir", "nested", "log.json")
        
        # Directory doesn't exist yet
        assert not os.path.exists(os.path.dirname(nested_path))
        
        # Create tracker with nested path
        tracker = CreditTracker(log_file=nested_path)
        
        # Directory should be created
        assert os.path.exists(os.path.dirname(nested_path))
        
        # Cleanup
        os.rmdir(os.path.dirname(nested_path))
        os.rmdir(os.path.dirname(os.path.dirname(nested_path)))
    
    def test_zero_division_protection(self):
        """Test protection against zero division in projections"""
        with patch('credit_tracker.datetime') as mock_datetime:
            # Mock current time to be beginning of month (day 0 would cause division by zero)
            mock_now = datetime(2023, 6, 1)
            mock_datetime.now.return_value = mock_now
            
            projection = self.tracker.project_monthly_usage()
            
            # Should not crash and should return sensible defaults
            assert projection['query_credits']['projected_eom'] == 0
            assert projection['scan_credits']['projected_eom'] == 0


class TestCreditTrackerIntegration:
    """Integration tests for credit tracker"""
    
    def test_full_workflow(self):
        """Test complete workflow"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
            tmp_name = tmp.name
        
        try:
            # Create tracker and log some usage
            tracker = CreditTracker(log_file=tmp_name)
            
            # Log several entries
            tracker.log_usage(5, 10, 'quick', 'Daily scan 1')
            tracker.log_usage(3, 8, 'quick', 'Daily scan 2')
            tracker.log_usage(10, 25, 'full', 'Weekly scan')
            
            # Get statistics
            monthly = tracker.get_monthly_usage()
            projection = tracker.project_monthly_usage(plan_limit=100)
            recommendations = tracker.get_recommendations(projection)
            
            # Verify results
            assert monthly['total_scans'] == 3
            assert monthly['query_credits_used'] == 18
            assert monthly['scan_credits_used'] == 43
            
            assert 'quick' in monthly['scan_type_breakdown']
            assert 'full' in monthly['scan_type_breakdown']
            assert monthly['scan_type_breakdown']['quick'] == 2
            assert monthly['scan_type_breakdown']['full'] == 1
            
            assert isinstance(projection, dict)
            assert isinstance(recommendations, list)
            
            # Test persistence
            new_tracker = CreditTracker(log_file=tmp_name)
            assert len(new_tracker.history) == 3
            
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)


if __name__ == "__main__":
    pytest.main([__file__])