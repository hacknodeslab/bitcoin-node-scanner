#!/usr/bin/env python3
"""
Bitcoin Node Security Reporter
Report generation and data export functionality
"""

import json
import csv
from datetime import datetime
from typing import Dict, List


class SecurityReporter:
    """Generates reports and exports scan data"""
    
    def __init__(self, config, analyzer):
        """
        Initialize reporter
        
        Args:
            config: Configuration object
            analyzer: SecurityAnalyzer instance
        """
        self.config = config
        self.analyzer = analyzer
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def _calculate_percentage(self, count: int, total: int) -> float:
        """Calculate percentage with zero division protection"""
        return (count / total * 100) if total > 0 else 0
    
    def _add_report_header(self, report: List[str]) -> None:
        """Add report header section"""
        report.append("="*80)
        report.append("BITCOIN NODE SECURITY SCAN REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Scan ID: {self.timestamp}")
        report.append("="*80)
        report.append("")
    
    def _add_executive_summary(self, report: List[str], stats: Dict) -> None:
        """Add executive summary section"""
        report.append("EXECUTIVE SUMMARY")
        report.append("-"*80)
        report.append(f"Total nodes found: {stats['total_results']}")
        report.append(f"Unique IPs: {stats['unique_ips']}")
        report.append(f"Vulnerable nodes: {stats.get('vulnerable_nodes', 0)}")
        report.append(f"RPC exposed: {stats.get('rpc_exposed', 0)} (CRITICAL)")
        report.append(f"Dev versions: {stats.get('dev_versions', 0)}")
        report.append("")
    
    def _add_risk_distribution(self, report: List[str], stats: Dict) -> None:
        """Add risk distribution section"""
        report.append("RISK DISTRIBUTION")
        report.append("-"*80)
        risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for risk_level in risk_order:
            count = stats.get('risk_distribution', {}).get(risk_level, 0)
            percentage = self._calculate_percentage(count, stats['total_results'])
            report.append(f"{risk_level:12} {count:6} ({percentage:5.2f}%)")
        report.append("")
    
    def _add_port_distribution(self, report: List[str], stats: Dict) -> None:
        """Add port distribution section"""
        report.append("PORT DISTRIBUTION")
        report.append("-"*80)
        for port, count in sorted(stats['port_distribution'].items(), key=lambda x: x[1], reverse=True):
            port_name = self.config.BITCOIN_PORTS.get(port, 'Unknown')
            percentage = self._calculate_percentage(count, stats['total_results'])
            report.append(f"{port:6} ({port_name:30}) {count:6} ({percentage:5.2f}%)")
        report.append("")
    
    def _get_version_flags(self, version: str) -> str:
        """Get vulnerability and dev flags for version"""
        vulnerable = "⚠ VULNERABLE" if self.analyzer.is_vulnerable_version(version) else ""
        dev = "🔧 DEV" if self.analyzer.is_dev_version(version) else ""
        return f"{vulnerable} {dev}".strip()
    
    def _add_version_distribution(self, report: List[str], stats: Dict) -> None:
        """Add version distribution section"""
        report.append("TOP 20 VERSIONS")
        report.append("-"*80)
        for version, count in list(stats['version_distribution'].items())[:20]:
            percentage = self._calculate_percentage(count, stats['total_results'])
            flags = self._get_version_flags(version)
            report.append(f"{version:40} {count:6} ({percentage:5.2f}%) {flags}")
        report.append("")
    
    def _add_country_distribution(self, report: List[str], stats: Dict) -> None:
        """Add country distribution section"""
        report.append("TOP 20 COUNTRIES")
        report.append("-"*80)
        for country, count in list(stats['country_distribution'].items())[:20]:
            percentage = self._calculate_percentage(count, stats['total_results'])
            report.append(f"{country:6} {count:6} ({percentage:5.2f}%)")
        report.append("")
    
    def _add_asn_distribution(self, report: List[str], stats: Dict) -> None:
        """Add ASN distribution section"""
        report.append("TOP 20 ASNs")
        report.append("-"*80)
        for asn, count in list(stats['asn_distribution'].items())[:20]:
            percentage = self._calculate_percentage(count, stats['total_results'])
            report.append(f"{asn:15} {count:6} ({percentage:5.2f}%)")
        report.append("")
    
    def _add_report_footer(self, report: List[str]) -> None:
        """Add report footer section"""
        report.append("="*80)
        report.append("END OF REPORT")
        report.append("="*80)
    
    def generate_text_report(self, stats: Dict, results: List[Dict]) -> str:
        """
        Generate human-readable text report
        
        Args:
            stats: Statistics dictionary
            results: List of scan results
            
        Returns:
            Formatted text report
        """
        report = []
        
        self._add_report_header(report)
        self._add_executive_summary(report, stats)
        self._add_risk_distribution(report, stats)
        self._add_port_distribution(report, stats)
        self._add_version_distribution(report, stats)
        self._add_country_distribution(report, stats)
        self._add_asn_distribution(report, stats)
        self._add_report_footer(report)
        
        return '\n'.join(report)
    
    def save_text_report(self, stats: Dict, results: List[Dict]) -> str:
        """
        Save text report to file
        
        Args:
            stats: Statistics dictionary
            results: List of scan results
            
        Returns:
            Path to saved report
        """
        report_text = self.generate_text_report(stats, results)
        filename = f"{self.config.REPORTS_DIR}/report_{self.timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(report_text)
        
        return filename
    
    def save_json_data(self, data: Dict, prefix: str, subdir: str = None) -> str:
        """
        Save data as JSON file
        
        Args:
            data: Data to save
            prefix: Filename prefix
            subdir: Subdirectory (raw_data, reports, etc.)
            
        Returns:
            Path to saved file
        """
        if subdir:
            directory = f"{self.config.OUTPUT_DIR}/{subdir}"
        else:
            directory = self.config.OUTPUT_DIR
        
        filename = f"{directory}/{prefix}_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename
    
    def save_csv_data(self, data: List[Dict], prefix: str, subdir: str = None) -> str:
        """
        Save data as CSV file
        
        Args:
            data: List of dictionaries to save
            prefix: Filename prefix
            subdir: Subdirectory
            
        Returns:
            Path to saved file
        """
        if not data:
            return None
        
        if subdir:
            directory = f"{self.config.OUTPUT_DIR}/{subdir}"
        else:
            directory = self.config.OUTPUT_DIR
        
        filename = f"{directory}/{prefix}_{self.timestamp}.csv"
        
        # Get all unique keys from all dictionaries
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
            writer.writeheader()
            
            for row in data:
                # Clean complex types for CSV
                row_clean = {}
                for k, v in row.items():
                    if isinstance(v, (list, dict)):
                        row_clean[k] = json.dumps(v)
                    else:
                        row_clean[k] = v
                writer.writerow(row_clean)
        
        return filename
    
    def save_raw_data(self, results: List[Dict]) -> tuple:
        """
        Save raw scan results in JSON and CSV formats
        
        Args:
            results: List of scan results
            
        Returns:
            Tuple of (json_path, csv_path)
        """
        json_path = self.save_json_data(results, 'nodes', 'raw_data')
        csv_path = self.save_csv_data(results, 'nodes', 'raw_data')
        
        return json_path, csv_path
    
    def save_statistics(self, stats: Dict) -> str:
        """
        Save statistics to JSON file
        
        Args:
            stats: Statistics dictionary
            
        Returns:
            Path to saved file
        """
        return self.save_json_data(stats, 'statistics', 'reports')
    
    def save_critical_nodes(self, critical_nodes: List[Dict]) -> tuple:
        """
        Save critical nodes list in JSON and CSV formats
        
        Args:
            critical_nodes: List of critical node dictionaries
            
        Returns:
            Tuple of (json_path, csv_path)
        """
        json_path = self.save_json_data(critical_nodes, 'critical_nodes', 'reports')
        csv_path = self.save_csv_data(critical_nodes, 'critical_nodes', 'reports')
        
        return json_path, csv_path
    
    def generate_summary_table(self, stats: Dict) -> str:
        """
        Generate a quick summary table
        
        Args:
            stats: Statistics dictionary
            
        Returns:
            Formatted summary table
        """
        summary = []
        summary.append("\n" + "="*60)
        summary.append("QUICK SUMMARY")
        summary.append("="*60)
        
        # Key metrics
        summary.append(f"Total Nodes:        {stats['total_results']:,}")
        summary.append(f"Unique IPs:         {stats['unique_ips']:,}")
        summary.append(f"Vulnerable:         {stats.get('vulnerable_nodes', 0):,}")
        summary.append(f"RPC Exposed:        {stats.get('rpc_exposed', 0):,}")
        summary.append(f"Dev Versions:       {stats.get('dev_versions', 0):,}")
        
        summary.append("-"*60)
        
        # Risk breakdown
        risk_dist = stats.get('risk_distribution', {})
        summary.append("Risk Levels:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_dist.get(level, 0)
            pct = (count / stats['total_results'] * 100) if stats['total_results'] > 0 else 0
            summary.append(f"  {level:10} {count:6,} ({pct:5.2f}%)")
        
        summary.append("="*60 + "\n")
        
        return '\n'.join(summary)
    
    def export_results(self, results: List[Dict], stats: Dict, 
                      critical_nodes: List[Dict]) -> Dict:
        """
        Export all results in various formats
        
        Args:
            results: Scan results
            stats: Statistics
            critical_nodes: Critical nodes list
            
        Returns:
            Dictionary with paths to all exported files
        """
        exports = {}
        
        # Raw data
        json_path, csv_path = self.save_raw_data(results)
        exports['raw_json'] = json_path
        exports['raw_csv'] = csv_path
        
        # Statistics
        exports['statistics'] = self.save_statistics(stats)
        
        # Text report
        exports['text_report'] = self.save_text_report(stats, results)
        
        # Critical nodes
        crit_json, crit_csv = self.save_critical_nodes(critical_nodes)
        exports['critical_json'] = crit_json
        exports['critical_csv'] = crit_csv
        
        return exports
    
    def print_report(self, stats: Dict, results: List[Dict]):
        """
        Print report to console
        
        Args:
            stats: Statistics dictionary
            results: List of scan results
        """
        report = self.generate_text_report(stats, results)
        print("\n" + report)
    
    def print_summary(self, stats: Dict):
        """
        Print quick summary to console
        
        Args:
            stats: Statistics dictionary
        """
        summary = self.generate_summary_table(stats)
        print(summary)
