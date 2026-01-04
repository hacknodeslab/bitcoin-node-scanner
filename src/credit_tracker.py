#!/usr/bin/env python3
"""
Shodan Credit Usage Tracker
Monitor and report API credit consumption
"""

import json
import os
from datetime import datetime
from typing import Dict, List


class CreditTracker:
    """Track Shodan API credit usage over time"""
    
    def __init__(self, log_file: str = 'output/logs/credit_usage.json'):
        self.log_file = log_file
        self.history = self._load_history()
        self._ensure_log_dir()
    
    def _ensure_log_dir(self):
        """Create log directory if needed"""
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
    
    def _load_history(self) -> List[Dict]:
        """Load usage history"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def save_history(self):
        """Save usage history"""
        with open(self.log_file, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def log_usage(self, query_credits: int, scan_credits: int, 
                  scan_type: str = 'manual', notes: str = ''):
        """
        Log credit usage
        
        Args:
            query_credits: Query credits used
            scan_credits: Scan credits used
            scan_type: Type of scan (quick/medium/full)
            notes: Additional notes
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'query_credits_used': query_credits,
            'scan_credits_used': scan_credits,
            'scan_type': scan_type,
            'notes': notes
        }
        
        self.history.append(entry)
        self.save_history()
    
    def get_monthly_usage(self, year: int = None, month: int = None) -> Dict:
        """
        Calculate usage for a specific month
        
        Args:
            year: Year (default: current)
            month: Month (default: current)
            
        Returns:
            Dictionary with usage statistics
        """
        now = datetime.now()
        year = year or now.year
        month = month or now.month
        
        # Filter entries for this month
        monthly_entries = []
        for entry in self.history:
            entry_date = datetime.fromisoformat(entry['timestamp'])
            if entry_date.year == year and entry_date.month == month:
                monthly_entries.append(entry)
        
        # Calculate totals
        total_query = sum(e['query_credits_used'] for e in monthly_entries)
        total_scan = sum(e['scan_credits_used'] for e in monthly_entries)
        
        # Count by scan type
        scan_types = {}
        for entry in monthly_entries:
            scan_type = entry.get('scan_type', 'unknown')
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        return {
            'year': year,
            'month': month,
            'total_scans': len(monthly_entries),
            'query_credits_used': total_query,
            'scan_credits_used': total_scan,
            'scan_type_breakdown': scan_types,
            'entries': monthly_entries
        }
    
    def project_monthly_usage(self, plan_limit: int = 100, 
                               current_query_credits: int = None,
                               current_scan_credits: int = None) -> Dict:
        """
        Project end-of-month usage based on current rate
        
        Args:
            plan_limit: Monthly credit limit (default: 100 for Membership)
            current_query_credits: Current query credits from API (real-time)
            current_scan_credits: Current scan credits from API (real-time)
            
        Returns:
            Projection dictionary
        """
        now = datetime.now()
        monthly = self.get_monthly_usage()
        
        # Days elapsed and remaining
        days_in_month = 30  # Approximation
        day_of_month = now.day
        days_remaining = days_in_month - day_of_month
        
        # Calculate daily average
        if day_of_month > 0:
            query_per_day = monthly['query_credits_used'] / day_of_month
            scan_per_day = monthly['scan_credits_used'] / day_of_month
        else:
            query_per_day = 0
            scan_per_day = 0
        
        # Project end of month
        projected_query = monthly['query_credits_used'] + (query_per_day * days_remaining)
        projected_scan = monthly['scan_credits_used'] + (scan_per_day * days_remaining)
        
        # Use real API credits if provided, otherwise fall back to calculated values
        query_remaining = (current_query_credits if current_query_credits is not None 
                          else plan_limit - monthly['query_credits_used'])
        scan_remaining = (current_scan_credits if current_scan_credits is not None 
                         else plan_limit - monthly['scan_credits_used'])
        
        return {
            'current_usage': monthly,
            'days_elapsed': day_of_month,
            'days_remaining': days_remaining,
            'query_credits': {
                'used': monthly['query_credits_used'],
                'projected_eom': round(projected_query),
                'limit': plan_limit,
                'remaining': query_remaining,
                'projected_remaining': query_remaining - round(projected_query - monthly['query_credits_used']),
                'api_current': current_query_credits,
            },
            'scan_credits': {
                'used': monthly['scan_credits_used'],
                'projected_eom': round(projected_scan),
                'limit': plan_limit,
                'remaining': scan_remaining,
                'projected_remaining': scan_remaining - round(projected_scan - monthly['scan_credits_used']),
                'api_current': current_scan_credits,
            }
        }
    
    def get_recommendations(self, projection: Dict) -> List[str]:
        """
        Get recommendations based on projected usage
        
        Args:
            projection: Projection from project_monthly_usage()
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # Query credits
        query_proj = projection['query_credits']['projected_eom']
        query_limit = projection['query_credits']['limit']
        query_usage_pct = (query_proj / query_limit * 100) if query_limit > 0 else 0
        
        if query_usage_pct > 100:
            recommendations.append(
                f"⚠️  WARNING: Projected to exceed query credit limit by "
                f"{query_proj - query_limit} credits ({query_usage_pct:.0f}% usage)"
            )
            recommendations.append("   → Consider reducing scan frequency")
            recommendations.append("   → Enable caching if not already active")
            recommendations.append("   → Use optimized queries")
        elif query_usage_pct > 80:
            recommendations.append(
                f"⚡ High query credit usage projected: {query_usage_pct:.0f}%"
            )
            recommendations.append("   → Monitor usage closely")
            recommendations.append("   → Consider spacing out scans")
        elif query_usage_pct < 50:
            recommendations.append(
                f"✅ Good query credit usage: {query_usage_pct:.0f}% projected"
            )
            recommendations.append("   → You can increase scan frequency if needed")
        
        # Scan credits
        scan_proj = projection['scan_credits']['projected_eom']
        scan_limit = projection['scan_credits']['limit']
        scan_usage_pct = (scan_proj / scan_limit * 100) if scan_limit > 0 else 0
        
        if scan_usage_pct > 100:
            recommendations.append(
                f"⚠️  WARNING: Projected to exceed scan credit limit by "
                f"{scan_proj - scan_limit} credits ({scan_usage_pct:.0f}% usage)"
            )
            recommendations.append("   → Reduce enrichment scope")
            recommendations.append("   → Only enrich CRITICAL nodes")
        elif scan_usage_pct > 80:
            recommendations.append(
                f"⚡ High scan credit usage projected: {scan_usage_pct:.0f}%"
            )
            recommendations.append("   → Limit enrichment to critical nodes only")
        elif scan_usage_pct < 50:
            recommendations.append(
                f"✅ Good scan credit usage: {scan_usage_pct:.0f}% projected"
            )
        
        return recommendations
    
    def print_report(self, projection: Dict = None):
        """Print usage report to console"""
        monthly = self.get_monthly_usage()
        if projection is None:
            projection = self.project_monthly_usage()
        recommendations = self.get_recommendations(projection)
        
        print("\n" + "="*80)
        print("SHODAN CREDIT USAGE REPORT")
        print("="*80)
        
        # Current month
        print(f"\nMonth: {monthly['year']}-{monthly['month']:02d}")
        print(f"Total scans: {monthly['total_scans']}")
        print()
        
        # Query credits
        print("QUERY CREDITS:")
        print(f"  Used:              {monthly['query_credits_used']}")
        print(f"  Projected (EOM):   {projection['query_credits']['projected_eom']}")
        print(f"  Limit:             {projection['query_credits']['limit']}")
        if projection['query_credits']['api_current'] is not None:
            print(f"  Remaining (API):   {projection['query_credits']['remaining']}")
            print(f"  Projected remain:  {projection['query_credits']['projected_remaining']}")
        else:
            print(f"  Remaining:         {projection['query_credits']['remaining']}")
            print(f"  Projected remain:  {projection['query_credits']['projected_remaining']}")
        print()
        
        # Scan credits
        print("SCAN CREDITS:")
        print(f"  Used:              {monthly['scan_credits_used']}")
        print(f"  Projected (EOM):   {projection['scan_credits']['projected_eom']}")
        print(f"  Limit:             {projection['scan_credits']['limit']}")
        if projection['scan_credits']['api_current'] is not None:
            print(f"  Remaining (API):   {projection['scan_credits']['remaining']}")
            print(f"  Projected remain:  {projection['scan_credits']['projected_remaining']}")
        else:
            print(f"  Remaining:         {projection['scan_credits']['remaining']}")
            print(f"  Projected remain:  {projection['scan_credits']['projected_remaining']}")
        print()
        
        # Scan type breakdown
        if monthly['scan_type_breakdown']:
            print("SCAN TYPE BREAKDOWN:")
            for scan_type, count in monthly['scan_type_breakdown'].items():
                print(f"  {scan_type:12} {count}")
            print()
        
        # Recommendations
        if recommendations:
            print("RECOMMENDATIONS:")
            for rec in recommendations:
                print(rec)
            print()
        
        print("="*80)
        print()


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Shodan Credit Usage Tracker'
    )
    
    parser.add_argument('--log', action='store_true',
                       help='Log a manual usage entry')
    parser.add_argument('--query-credits', type=int, default=0,
                       help='Query credits used')
    parser.add_argument('--scan-credits', type=int, default=0,
                       help='Scan credits used')
    parser.add_argument('--type', default='manual',
                       help='Scan type (quick/medium/full)')
    parser.add_argument('--notes', default='',
                       help='Additional notes')
    parser.add_argument('--report', action='store_true',
                       help='Show usage report')
    
    args = parser.parse_args()
    
    tracker = CreditTracker()
    
    if args.log:
        tracker.log_usage(
            query_credits=args.query_credits,
            scan_credits=args.scan_credits,
            scan_type=args.type,
            notes=args.notes
        )
        print(f"Logged: {args.query_credits} query + {args.scan_credits} scan credits")
    
    if args.report or not args.log:
        tracker.print_report()


if __name__ == '__main__':
    main()
