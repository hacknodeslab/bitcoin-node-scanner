#!/usr/bin/env python3
"""
Bitcoin Node Security Scanner - HackNodes Lab
Comprehensive analysis of Bitcoin nodes exposed on clearnet using Shodan
"""

import shodan
import json
import csv
import time
from datetime import datetime
from collections import Counter
import argparse
import os
from typing import List, Dict, Set
import yaml

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Centralized configuration"""
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'YOUR_API_KEY_HERE')
    
    # Search queries
    QUERIES = [
        'product:Bitcoin',
        'port:8333',
        '"Satoshi" port:8333',
        'port:8332',  # RPC - CRITICAL
        '"Bitcoin Core"',
        '"Bitcoin Knots"',
        'bitcoin',
        '"btcd"',
        '"bcoin"',
    ]
    
    # Ports of interest
    BITCOIN_PORTS = {
        8333: 'P2P Mainnet',
        8332: 'RPC Mainnet (CRITICAL)',
        18333: 'P2P Testnet',
        18332: 'RPC Testnet',
        38333: 'P2P Signet',
        38332: 'RPC Signet',
        9735: 'Lightning Network',
        50001: 'Electrum TCP',
        50002: 'Electrum SSL',
    }
    
    # Additional high-risk ports
    HIGH_RISK_PORTS = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        9200: 'Elasticsearch',
        2375: 'Docker API',
        6443: 'Kubernetes API',
    }
    
    # Known vulnerable versions
    VULNERABLE_VERSIONS = {
        '0.13.0': 'Multiple CVEs',
        '0.13.1': 'Multiple CVEs',
        '0.13.2': 'Multiple CVEs',
        '0.14.0': 'CVE-2017-12842',
        '0.14.1': 'CVE-2017-12842',
        '0.14.2': 'CVE-2017-12842',
        '0.15.0': 'CVE-2018-17144',
        '0.15.1': 'CVE-2018-17144',
        '0.16.0': 'CVE-2018-17144',
        '0.16.1': 'CVE-2018-17144',
        '0.16.2': 'CVE-2018-17144',
        '0.16.3': 'Multiple CVEs',
        '0.17.0': 'Multiple CVEs',
        '0.17.1': 'Multiple CVEs',
        '0.18.0': 'Multiple CVEs',
        '0.18.1': 'Multiple CVEs',
        '0.19.0': 'Multiple CVEs',
        '0.19.1': 'Multiple CVEs',
        '0.20.0': 'Multiple CVEs',
        '0.20.1': 'Multiple CVEs',
        '0.21.0': 'CVE-2021-31876',
        '0.21.1': 'CVE-2021-31876',
    }
    
    # Output directories
    OUTPUT_DIR = 'output'
    RAW_DATA_DIR = f'{OUTPUT_DIR}/raw_data'
    REPORTS_DIR = f'{OUTPUT_DIR}/reports'
    LOGS_DIR = f'{OUTPUT_DIR}/logs'

# ============================================================================
# MAIN CLASS
# ============================================================================

class BitcoinNodeScanner:
    """Main Bitcoin node scanner"""
    
    def __init__(self, api_key: str = None):
        """Initialize scanner"""
        self.api_key = api_key or Config.SHODAN_API_KEY
        if not self.api_key or self.api_key == 'YOUR_API_KEY_HERE':
            raise ValueError("Please set SHODAN_API_KEY environment variable")
        
        self.api = shodan.Shodan(self.api_key)
        self.results = []
        self.unique_ips = set()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create directories
        for directory in [Config.OUTPUT_DIR, Config.RAW_DATA_DIR, 
                         Config.REPORTS_DIR, Config.LOGS_DIR]:
            os.makedirs(directory, exist_ok=True)
        
        # Logging
        self.log_file = f"{Config.LOGS_DIR}/scan_{self.timestamp}.log"
        self.log(f"Initializing Bitcoin Node Scanner - {self.timestamp}")
    
    def log(self, message: str, level: str = 'INFO'):
        """Simple logger"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        with open(self.log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def get_account_info(self):
        """Check Shodan credits"""
        try:
            info = self.api.info()
            self.log(f"Shodan query credits: {info.get('query_credits', 'N/A')}")
            self.log(f"Scan credits: {info.get('scan_credits', 'N/A')}")
            return info
        except Exception as e:
            self.log(f"Error getting account info: {e}", 'ERROR')
            return None
    
    def search_bitcoin_nodes(self, query: str, max_results: int = 1000) -> List[Dict]:
        """Search nodes with a specific query"""
        self.log(f"Searching: '{query}'")
        results = []
        
        try:
            # Initial search
            search_results = self.api.search(query)
            total = search_results['total']
            self.log(f"Total found for '{query}': {total}")
            
            # Paginate results
            page = 1
            collected = 0
            
            while collected < min(max_results, total):
                try:
                    if page > 1:
                        search_results = self.api.search(query, page=page)
                    
                    for result in search_results['matches']:
                        if collected >= max_results:
                            break
                        
                        # Process result
                        node_data = self.parse_node_data(result, query)
                        results.append(node_data)
                        self.unique_ips.add(result['ip_str'])
                        collected += 1
                    
                    page += 1
                    time.sleep(1)  # Rate limiting
                    
                except shodan.APIError as e:
                    if 'upgrade your API plan' in str(e).lower():
                        self.log(f"Limit reached at page {page}. Collected: {collected}", 'WARNING')
                        break
                    else:
                        raise
            
            self.log(f"Collected {collected} results for '{query}'")
            
        except shodan.APIError as e:
            self.log(f"Error in search '{query}': {e}", 'ERROR')
        
        return results
    
    def parse_node_data(self, result: Dict, query: str) -> Dict:
        """Parse node data"""
        return {
            'timestamp': self.timestamp,
            'query': query,
            'ip': result.get('ip_str'),
            'port': result.get('port'),
            'transport': result.get('transport', 'tcp'),
            'product': result.get('product', ''),
            'version': result.get('version', ''),
            'banner': result.get('data', ''),
            'organization': result.get('org', ''),
            'isp': result.get('isp', ''),
            'asn': result.get('asn', ''),
            'country': result.get('location', {}).get('country_name', ''),
            'country_code': result.get('location', {}).get('country_code', ''),
            'city': result.get('location', {}).get('city', ''),
            'hostnames': result.get('hostnames', []),
            'domains': result.get('domains', []),
            'timestamp_shodan': result.get('timestamp', ''),
            'ssl': self.extract_ssl_info(result),
            'vulns': result.get('vulns', []),
            'cpe': result.get('cpe', []),
        }
    
    def extract_ssl_info(self, result: Dict) -> Dict:
        """Extract SSL information if available"""
        ssl_info = {}
        if 'ssl' in result:
            ssl_data = result['ssl']
            ssl_info = {
                'enabled': True,
                'version': ssl_data.get('version', ''),
                'cipher': ssl_data.get('cipher', {}).get('name', ''),
                'cert_issued': ssl_data.get('cert', {}).get('issued', ''),
                'cert_expires': ssl_data.get('cert', {}).get('expires', ''),
                'cert_subject': ssl_data.get('cert', {}).get('subject', {}),
            }
        return ssl_info
    
    def scan_all_queries(self, max_per_query: int = 1000):
        """Execute all configured queries"""
        self.log("="*80)
        self.log("STARTING FULL SCAN")
        self.log("="*80)
        
        for query in Config.QUERIES:
            results = self.search_bitcoin_nodes(query, max_per_query)
            self.results.extend(results)
            time.sleep(2)  # Cooldown between queries
        
        self.log(f"\nTotal results: {len(self.results)}")
        self.log(f"Unique IPs: {len(self.unique_ips)}")
    
    def enrich_with_host_scan(self, ip: str) -> Dict:
        """Get complete host information"""
        try:
            host = self.api.host(ip)
            return {
                'all_ports': [service['port'] for service in host.get('data', [])],
                'all_services': [
                    {
                        'port': service.get('port'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                    }
                    for service in host.get('data', [])
                ],
                'tags': host.get('tags', []),
                'vulns': host.get('vulns', []),
                'os': host.get('os', ''),
                'last_update': host.get('last_update', ''),
            }
        except Exception as e:
            self.log(f"Error enriching {ip}: {e}", 'WARNING')
            return {}
    
    def enrich_critical_nodes(self, max_enrichments: int = 100):
        """Enrich critical nodes with full host scan"""
        self.log("\nEnriching critical nodes...")
        
        # Filter critical nodes (RPC exposed or very old versions)
        critical_ips = set()
        
        for result in self.results:
            if result['port'] == 8332:  # RPC
                critical_ips.add(result['ip'])
            elif self.is_vulnerable_version(result.get('version', '')):
                critical_ips.add(result['ip'])
        
        self.log(f"Critical nodes identified: {len(critical_ips)}")
        
        enriched = 0
        for ip in list(critical_ips)[:max_enrichments]:
            enrichment = self.enrich_with_host_scan(ip)
            
            # Update results
            for result in self.results:
                if result['ip'] == ip:
                    result['enrichment'] = enrichment
            
            enriched += 1
            if enriched % 10 == 0:
                self.log(f"Enriched: {enriched}/{min(max_enrichments, len(critical_ips))}")
            
            time.sleep(1)  # Rate limiting
        
        self.log(f"Enrichment completed: {enriched} hosts")
    
    def is_vulnerable_version(self, version: str) -> bool:
        """Check if version is known vulnerable"""
        # Extract version from banner/product
        for vuln_version in Config.VULNERABLE_VERSIONS.keys():
            if vuln_version in version:
                return True
        
        # Very old versions (< 0.21)
        try:
            if 'Satoshi:0.' in version:
                ver_num = version.split(':')[1].split('.')[1]
                if int(ver_num) < 21:
                    return True
        except:
            pass
        
        return False
    
    def analyze_risk_level(self, result: Dict) -> str:
        """Determine node risk level"""
        risk_factors = []
        
        # RPC port exposed
        if result['port'] == 8332:
            return 'CRITICAL'
        
        # Known vulnerable version
        if self.is_vulnerable_version(result.get('version', '')):
            risk_factors.append('vulnerable_version')
        
        # Development version in production
        if '.99.' in result.get('version', ''):
            risk_factors.append('dev_version')
        
        # Multiple services (if enriched)
        enrichment = result.get('enrichment', {})
        if enrichment:
            ports = enrichment.get('all_ports', [])
            high_risk_exposed = [p for p in ports if p in Config.HIGH_RISK_PORTS]
            if len(high_risk_exposed) > 2:
                risk_factors.append('multiple_services')
        
        # Determine level
        if len(risk_factors) >= 2:
            return 'HIGH'
        elif len(risk_factors) == 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_statistics(self) -> Dict:
        """Generate scan statistics"""
        stats = {
            'total_results': len(self.results),
            'unique_ips': len(self.unique_ips),
            'timestamp': self.timestamp,
        }
        
        # Port distribution
        port_dist = Counter(r['port'] for r in self.results)
        stats['port_distribution'] = dict(port_dist)
        
        # Country distribution
        country_dist = Counter(r['country_code'] for r in self.results if r['country_code'])
        stats['country_distribution'] = dict(country_dist.most_common(20))
        
        # Version distribution
        version_dist = Counter()
        for r in self.results:
            version = self.extract_version_from_banner(r)
            if version:
                version_dist[version] += 1
        stats['version_distribution'] = dict(version_dist.most_common(50))
        
        # ASN distribution
        asn_dist = Counter(r['asn'] for r in self.results if r['asn'])
        stats['asn_distribution'] = dict(asn_dist.most_common(20))
        
        # Risk levels
        risk_dist = Counter()
        for r in self.results:
            risk = self.analyze_risk_level(r)
            risk_dist[risk] += 1
        stats['risk_distribution'] = dict(risk_dist)
        
        # Vulnerable versions count
        vulnerable_count = sum(
            1 for r in self.results 
            if self.is_vulnerable_version(r.get('version', ''))
        )
        stats['vulnerable_nodes'] = vulnerable_count
        
        # RPC exposed
        rpc_exposed = sum(1 for r in self.results if r['port'] == 8332)
        stats['rpc_exposed'] = rpc_exposed
        
        return stats
    
    def extract_version_from_banner(self, result: Dict) -> str:
        """Extract version from banner or product"""
        banner = result.get('banner', '')
        product = result.get('product', '')
        version = result.get('version', '')
        
        # Try to extract from banner
        if '/Satoshi:' in banner:
            try:
                version_part = banner.split('/Satoshi:')[1].split('/')[0]
                return f"Satoshi:{version_part}"
            except:
                pass
        
        if product and version:
            return f"{product}:{version}"
        
        return version or 'Unknown'
    
    def save_raw_data(self):
        """Save raw data"""
        filename = f"{Config.RAW_DATA_DIR}/nodes_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.log(f"Raw data saved: {filename}")
        
        # Also CSV
        csv_filename = f"{Config.RAW_DATA_DIR}/nodes_{self.timestamp}.csv"
        
        if self.results:
            keys = self.results[0].keys()
            with open(csv_filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for row in self.results:
                    # Convert lists/dicts to strings for CSV
                    row_clean = {}
                    for k, v in row.items():
                        if isinstance(v, (list, dict)):
                            row_clean[k] = json.dumps(v)
                        else:
                            row_clean[k] = v
                    writer.writerow(row_clean)
            
            self.log(f"CSV saved: {csv_filename}")
    
    def save_statistics(self, stats: Dict):
        """Save statistics"""
        filename = f"{Config.REPORTS_DIR}/statistics_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(stats, f, indent=2)
        
        self.log(f"Statistics saved: {filename}")
    
    def generate_report(self, stats: Dict):
        """Generate text report"""
        report = []
        report.append("="*80)
        report.append("BITCOIN NODE SECURITY SCAN REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Scan ID: {self.timestamp}")
        report.append("="*80)
        report.append("")
        
        # Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-"*80)
        report.append(f"Total nodes found: {stats['total_results']}")
        report.append(f"Unique IPs: {stats['unique_ips']}")
        report.append(f"Vulnerable nodes: {stats.get('vulnerable_nodes', 0)}")
        report.append(f"RPC exposed: {stats.get('rpc_exposed', 0)} (CRITICAL)")
        report.append("")
        
        # Risk distribution
        report.append("RISK DISTRIBUTION")
        report.append("-"*80)
        for risk_level, count in sorted(stats.get('risk_distribution', {}).items()):
            percentage = (count / stats['total_results'] * 100) if stats['total_results'] > 0 else 0
            report.append(f"{risk_level:12} {count:6} ({percentage:5.2f}%)")
        report.append("")
        
        # Port distribution
        report.append("PORT DISTRIBUTION")
        report.append("-"*80)
        for port, count in sorted(stats['port_distribution'].items(), key=lambda x: x[1], reverse=True):
            port_name = Config.BITCOIN_PORTS.get(port, 'Unknown')
            percentage = (count / stats['total_results'] * 100) if stats['total_results'] > 0 else 0
            report.append(f"{port:6} ({port_name:20}) {count:6} ({percentage:5.2f}%)")
        report.append("")
        
        # Top versions
        report.append("TOP 20 VERSIONS")
        report.append("-"*80)
        for version, count in list(stats['version_distribution'].items())[:20]:
            percentage = (count / stats['total_results'] * 100) if stats['total_results'] > 0 else 0
            vulnerable = "⚠ VULNERABLE" if self.is_vulnerable_version(version) else ""
            report.append(f"{version:40} {count:6} ({percentage:5.2f}%) {vulnerable}")
        report.append("")
        
        # Top countries
        report.append("TOP 20 COUNTRIES")
        report.append("-"*80)
        for country, count in list(stats['country_distribution'].items())[:20]:
            percentage = (count / stats['total_results'] * 100) if stats['total_results'] > 0 else 0
            report.append(f"{country:6} {count:6} ({percentage:5.2f}%)")
        report.append("")
        
        # Top ASNs
        report.append("TOP 20 ASNs")
        report.append("-"*80)
        for asn, count in list(stats['asn_distribution'].items())[:20]:
            percentage = (count / stats['total_results'] * 100) if stats['total_results'] > 0 else 0
            report.append(f"{asn:15} {count:6} ({percentage:5.2f}%)")
        report.append("")
        
        report.append("="*80)
        report.append("END OF REPORT")
        report.append("="*80)
        
        # Save
        report_text = '\n'.join(report)
        filename = f"{Config.REPORTS_DIR}/report_{self.timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(report_text)
        
        self.log(f"Report saved: {filename}")
        
        # Also print
        print("\n" + report_text)
    
    def generate_critical_nodes_list(self):
        """Generate critical nodes list for tracking"""
        critical_nodes = []
        
        for result in self.results:
            risk = self.analyze_risk_level(result)
            if risk in ['CRITICAL', 'HIGH']:
                critical_nodes.append({
                    'ip': result['ip'],
                    'port': result['port'],
                    'version': self.extract_version_from_banner(result),
                    'risk_level': risk,
                    'country': result['country_code'],
                    'organization': result['organization'],
                    'asn': result['asn'],
                    'reason': self.get_risk_reason(result, risk),
                })
        
        # Sort by risk level
        critical_nodes.sort(key=lambda x: (x['risk_level'] == 'CRITICAL', x['risk_level'] == 'HIGH'), reverse=True)
        
        # Save
        filename = f"{Config.REPORTS_DIR}/critical_nodes_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(critical_nodes, f, indent=2)
        
        self.log(f"Critical nodes list saved: {filename}")
        self.log(f"Total critical nodes: {len(critical_nodes)}")
        
        # CSV also
        csv_filename = f"{Config.REPORTS_DIR}/critical_nodes_{self.timestamp}.csv"
        if critical_nodes:
            with open(csv_filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=critical_nodes[0].keys())
                writer.writeheader()
                writer.writerows(critical_nodes)
        
        return critical_nodes
    
    def get_risk_reason(self, result: Dict, risk_level: str) -> str:
        """Get risk level reason"""
        reasons = []
        
        if result['port'] == 8332:
            reasons.append("RPC_EXPOSED")
        
        if self.is_vulnerable_version(result.get('version', '')):
            reasons.append("VULNERABLE_VERSION")
        
        if '.99.' in result.get('version', ''):
            reasons.append("DEV_VERSION")
        
        enrichment = result.get('enrichment', {})
        if enrichment:
            ports = enrichment.get('all_ports', [])
            high_risk_exposed = [p for p in ports if p in Config.HIGH_RISK_PORTS]
            if len(high_risk_exposed) > 2:
                reasons.append(f"MULTIPLE_SERVICES({len(high_risk_exposed)})")
        
        return ', '.join(reasons) if reasons else 'UNKNOWN'
    
    def run_full_scan(self, max_per_query: int = 1000, enrich: bool = True):
        """Run full scan"""
        # Check account
        self.get_account_info()
        
        # Scan
        self.scan_all_queries(max_per_query)
        
        # Enrich critical nodes
        if enrich and self.results:
            self.enrich_critical_nodes()
        
        # Generate statistics
        stats = self.generate_statistics()
        
        # Save everything
        self.save_raw_data()
        self.save_statistics(stats)
        self.generate_report(stats)
        self.generate_critical_nodes_list()
        
        self.log("\n" + "="*80)
        self.log("SCAN COMPLETED")
        self.log("="*80)

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Bitcoin Node Security Scanner - HackNodes Lab',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  
  # Basic scan
  python scanner.py
  
  # Scan with more results per query
  python scanner.py --max-per-query 2000
  
  # Scan without enrichment
  python scanner.py --no-enrich
  
  # Only check credits
  python scanner.py --check-credits
        """
    )
    
    parser.add_argument(
        '--api-key',
        help='Shodan API key (or use SHODAN_API_KEY variable)',
        default=None
    )
    
    parser.add_argument(
        '--max-per-query',
        type=int,
        default=1000,
        help='Maximum results per query (default: 1000)'
    )
    
    parser.add_argument(
        '--no-enrich',
        action='store_true',
        help='Do not enrich critical nodes with host scan'
    )
    
    parser.add_argument(
        '--check-credits',
        action='store_true',
        help='Only check Shodan credits and exit'
    )
    
    args = parser.parse_args()
    
    try:
        scanner = BitcoinNodeScanner(api_key=args.api_key)
        
        if args.check_credits:
            scanner.get_account_info()
            return
        
        scanner.run_full_scan(
            max_per_query=args.max_per_query,
            enrich=not args.no_enrich
        )
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())
