#!/usr/bin/env python3
"""
Optimized Bitcoin Node Scanner - Credit-Efficient Version
Implements strategies to minimize Shodan API credit usage
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from scanner import BitcoinNodeScanner, Config


class OptimizedConfig(Config):
    """Optimized configuration to reduce credit usage"""
    
    # Use optimized queries from environment if available, otherwise fall back to Config.QUERIES
    _QUERIES_OPTIMIZED_STRING = os.getenv('QUERIES_OPTIMIZED', 
        'product:Bitcoin port:8333,port:8332,Bitcoin Knots,btcd,bcoin')
    QUERIES_OPTIMIZED = [query.strip() for query in _QUERIES_OPTIMIZED_STRING.split(',') if query.strip()]
    
    # Cache settings
    CACHE_DIR = 'cache'
    CACHE_FILE = f'{CACHE_DIR}/nodes_cache.json'
    CACHE_MAX_AGE_DAYS = 7
    
    # Smart pagination limits
    MAX_RESULTS_CRITICAL = 1000    # For port 8332 (RPC)
    MAX_RESULTS_NORMAL = 100       # For other queries
    
    # Enrichment limits
    MAX_ENRICHMENTS = 100          # Stay within scan credit limit
    ENRICH_ONLY_CRITICAL = True    # Only enrich CRITICAL/HIGH nodes


class CachedNodeManager:
    """Manages cached node data to avoid re-scanning"""
    
    def __init__(self, cache_file: str = None):
        self.cache_file = cache_file or OptimizedConfig.CACHE_FILE
        self.cache = self._load_cache()
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
    
    def _load_cache(self) -> Dict:
        """Load cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def save_cache(self):
        """Save cache to file"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def is_cached(self, ip: str, max_age_days: int = None) -> bool:
        """
        Check if IP is in cache and recent enough
        
        Args:
            ip: IP address
            max_age_days: Maximum age in days (default from config)
            
        Returns:
            True if cached and fresh, False otherwise
        """
        max_age = max_age_days or OptimizedConfig.CACHE_MAX_AGE_DAYS
        
        if ip not in self.cache:
            return False
        
        cached_date = datetime.fromisoformat(self.cache[ip]['timestamp'])
        age = datetime.now() - cached_date
        
        return age < timedelta(days=max_age)
    
    def get_cached(self, ip: str) -> Optional[Dict]:
        """Get cached node data"""
        if self.is_cached(ip):
            return self.cache[ip]['data']
        return None
    
    def update_cache(self, nodes: List[Dict]):
        """Update cache with new node data"""
        timestamp = datetime.now().isoformat()
        
        for node in nodes:
            ip = node.get('ip')
            if ip:
                self.cache[ip] = {
                    'timestamp': timestamp,
                    'data': node
                }
        
        self.save_cache()
    
    def filter_uncached(self, nodes: List[Dict]) -> List[Dict]:
        """Filter out cached nodes"""
        return [n for n in nodes if not self.is_cached(n.get('ip', ''))]
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total = len(self.cache)
        fresh = sum(1 for ip in self.cache if self.is_cached(ip))
        stale = total - fresh
        
        return {
            'total_cached': total,
            'fresh': fresh,
            'stale': stale,
        }


class OptimizedBitcoinScanner(BitcoinNodeScanner):
    """Optimized scanner with credit-saving features"""
    
    def __init__(self, api_key: str = None, use_cache: bool = True):
        super().__init__(api_key)
        self.use_cache = use_cache
        self.cache_manager = CachedNodeManager() if use_cache else None
        self.credit_usage = {
            'query_credits_used': 0,
            'scan_credits_used': 0,
            'nodes_from_cache': 0,
            'nodes_scanned': 0,
        }
    
    def smart_search(self, query: str, is_critical: bool = False) -> List[Dict]:
        """
        Smart search with adaptive result limits
        
        Args:
            query: Search query
            is_critical: Whether this is a critical query (RPC, etc.)
            
        Returns:
            List of node results
        """
        # Determine max results based on criticality
        if is_critical:
            max_results = OptimizedConfig.MAX_RESULTS_CRITICAL
            self.log(f"Critical query - fetching up to {max_results} results")
        else:
            max_results = OptimizedConfig.MAX_RESULTS_NORMAL
            self.log(f"Normal query - fetching up to {max_results} results")
        
        # Search
        results = self.search_bitcoin_nodes(query, max_results)
        self.credit_usage['query_credits_used'] += 1
        self.credit_usage['nodes_scanned'] += len(results)
        
        return results
    
    def scan_optimized_queries(self) -> List[Dict]:
        """
        Scan using optimized query set
        
        Returns:
            Combined results from all queries
        """
        self.log("Starting optimized scan...")
        self.log(f"Using {len(OptimizedConfig.QUERIES_OPTIMIZED)} queries (vs 9 original)")
        
        all_results = []
        
        for query in OptimizedConfig.QUERIES_OPTIMIZED:
            # Check if critical query
            is_critical = 'port:8332' in query or 'RPC' in query
            
            results = self.smart_search(query, is_critical)
            all_results.extend(results)
        
        # Remove duplicates by IP
        unique_results = self._deduplicate_by_ip(all_results)
        
        self.log(f"Total results: {len(all_results)}, Unique IPs: {len(unique_results)}")
        
        return unique_results
    
    def _deduplicate_by_ip(self, results: List[Dict]) -> List[Dict]:
        """Remove duplicate IPs, keeping first occurrence"""
        seen_ips = set()
        unique = []
        
        for result in results:
            ip = result.get('ip')
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                unique.append(result)
        
        return unique
    
    def get_account_info(self):
        """Get account info and show credit usage report with real API values"""
        # Get parent implementation
        info = super().get_account_info()
        if not info:
            return info
        
        # Show credit usage report with real API values
        from credit_tracker import CreditTracker
        tracker = CreditTracker()
        
        # Get current credits from API
        query_credits = info.get('query_credits', 0)
        scan_credits = info.get('scan_credits', 0)
        
        # Generate projection with real API values
        projection = tracker.project_monthly_usage(
            current_query_credits=query_credits,
            current_scan_credits=scan_credits
        )
        
        # Print enhanced report with real API values
        tracker.print_report(projection)
        
        return info
    
    def scan_with_cache(self) -> List[Dict]:
        """
        Scan using cache to avoid re-scanning known nodes
        
        Returns:
            List of all nodes (cached + newly scanned)
        """
        if not self.use_cache:
            self.log("Cache disabled, performing full scan")
            return self.scan_optimized_queries()
        
        self.log("Checking cache...")
        cache_stats = self.cache_manager.get_stats()
        self.log(f"Cache status: {cache_stats['fresh']} fresh, {cache_stats['stale']} stale")
        
        # Perform scan
        new_results = self.scan_optimized_queries()
        
        # Filter out cached nodes
        uncached = self.cache_manager.filter_uncached(new_results)
        cached_count = len(new_results) - len(uncached)
        
        self.log(f"Found {cached_count} nodes in cache (skipping)")
        self.log(f"New nodes to process: {len(uncached)}")
        
        self.credit_usage['nodes_from_cache'] = cached_count
        
        # Update cache with new results
        self.cache_manager.update_cache(uncached)
        
        # Return all results (will use cached data for analysis)
        all_results = []
        for result in new_results:
            cached_data = self.cache_manager.get_cached(result['ip'])
            if cached_data:
                all_results.append(cached_data)
            else:
                all_results.append(result)
        
        return all_results
    
    def enrich_critical_only(self, results: List[Dict], max_enrichments: int = None):
        """
        Enrich only CRITICAL and HIGH risk nodes
        
        Args:
            results: List of node results
            max_enrichments: Maximum nodes to enrich (default from config)
        """
        max_enrich = max_enrichments or OptimizedConfig.MAX_ENRICHMENTS
        
        # Filter for critical nodes
        critical_nodes = []
        for result in results:
            risk = self.analyze_risk_level(result)
            if risk in ['CRITICAL', 'HIGH']:
                critical_nodes.append(result)
        
        self.log(f"Found {len(critical_nodes)} critical/high-risk nodes")
        
        # Limit to max enrichments
        to_enrich = critical_nodes[:max_enrich]
        
        if len(critical_nodes) > max_enrich:
            self.log(f"Limiting enrichment to {max_enrich} nodes (saving credits)")
        
        # Enrich
        enriched_count = 0
        for result in to_enrich:
            ip = result['ip']
            
            try:
                enrichment = self.enrich_with_host_scan(ip)
                result['enrichment'] = enrichment
                enriched_count += 1
                self.credit_usage['scan_credits_used'] += 1
            except Exception as e:
                self.log(f"Error enriching {ip}: {e}", 'WARNING')
        
        self.log(f"Enriched {enriched_count} critical nodes")
    
    def run_optimized_scan(self, use_cache: bool = True, 
                          enrich: bool = True,
                          max_enrichments: int = None):
        """
        Run optimized scan with all credit-saving features
        
        Args:
            use_cache: Use cached results
            enrich: Perform enrichment
            max_enrichments: Max nodes to enrich
        """
        self.log("="*80)
        self.log("OPTIMIZED SCAN - CREDIT EFFICIENT MODE")
        self.log("="*80)
        
        # Check account
        info = self.get_account_info()
        if info:
            query_credits = info.get('query_credits', 'N/A')
            scan_credits = info.get('scan_credits', 'N/A')
            self.log(f"Available credits - Query: {query_credits}, Scan: {scan_credits}")
        
        # Scan
        if use_cache:
            self.results = self.scan_with_cache()
        else:
            self.results = self.scan_optimized_queries()
        
        # Enrich (selective)
        if enrich and self.results:
            self.enrich_critical_only(self.results, max_enrichments)
        
        # Generate statistics
        stats = self.generate_statistics()
        
        # Save everything
        self.save_raw_data()
        self.save_statistics(stats)
        self.generate_report(stats)
        self.generate_critical_nodes_list()
        
        # Report credit usage
        self.log("\n" + "="*80)
        self.log("CREDIT USAGE SUMMARY")
        self.log("="*80)
        self.log(f"Query credits used: {self.credit_usage['query_credits_used']}")
        self.log(f"Scan credits used: {self.credit_usage['scan_credits_used']}")
        self.log(f"Nodes scanned: {self.credit_usage['nodes_scanned']}")
        self.log(f"Nodes from cache: {self.credit_usage['nodes_from_cache']}")
        
        if use_cache and self.credit_usage['nodes_from_cache'] > 0:
            savings_pct = (self.credit_usage['nodes_from_cache'] / 
                          (self.credit_usage['nodes_scanned'] + 
                           self.credit_usage['nodes_from_cache']) * 100)
            self.log(f"Cache savings: {savings_pct:.1f}%")
        
        self.log("="*80)
        self.log("OPTIMIZED SCAN COMPLETED")
        self.log("="*80)
        
        return stats


def main():
    """Main function for optimized scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Optimized Bitcoin Node Scanner - Credit Efficient',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Credit-Saving Features:
  - Optimized queries (5 instead of 9)
  - Smart pagination (adaptive limits)
  - Node caching (avoid re-scanning)
  - Selective enrichment (only critical nodes)
  
Usage examples:
  
  # Quick scan with all optimizations
  python optimized_scanner.py --quick
  
  # Full scan without cache
  python optimized_scanner.py --no-cache
  
  # Scan with limited enrichment
  python optimized_scanner.py --max-enrich 50
        """
    )
    
    parser.add_argument('--api-key', help='Shodan API key')
    parser.add_argument('--no-cache', action='store_true', 
                       help='Disable caching')
    parser.add_argument('--no-enrich', action='store_true',
                       help='Skip enrichment')
    parser.add_argument('--max-enrich', type=int, default=100,
                       help='Maximum nodes to enrich (default: 100)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan (cache + limited enrichment)')
    parser.add_argument('--check-credits', action='store_true',
                       help='Check credits and exit')
    
    args = parser.parse_args()
    
    try:
        scanner = OptimizedBitcoinScanner(
            api_key=args.api_key,
            use_cache=not args.no_cache
        )
        
        if args.check_credits:
            scanner.get_account_info()
            return 0
        
        # Quick mode
        if args.quick:
            scanner.run_optimized_scan(
                use_cache=True,
                enrich=True,
                max_enrichments=50  # Limit to 50 for quick scans
            )
        else:
            scanner.run_optimized_scan(
                use_cache=not args.no_cache,
                enrich=not args.no_enrich,
                max_enrichments=args.max_enrich
            )
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
