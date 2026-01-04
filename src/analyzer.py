#!/usr/bin/env python3
"""
Bitcoin Node Security Analyzer
Vulnerability detection and risk assessment logic
"""

from typing import Dict, List
from collections import Counter


class SecurityAnalyzer:
    """Analyzes Bitcoin nodes for security vulnerabilities and risks"""
    
    def __init__(self, config):
        """Initialize analyzer with configuration"""
        self.config = config
    
    def is_vulnerable_version(self, version: str) -> bool:
        """
        Check if version is known vulnerable
        
        Args:
            version: Version string from banner
            
        Returns:
            True if vulnerable, False otherwise
        """
        # Check against known vulnerable versions
        for vuln_version in self.config.VULNERABLE_VERSIONS.keys():
            if vuln_version in version:
                return True
        
        # Check for old versions (< 0.21)
        try:
            if 'Satoshi:0.' in version:
                ver_num = version.split(':')[1].split('.')[1]
                if int(ver_num) < 21:
                    return True
        except (IndexError, ValueError):
            pass
        
        return False
    
    def is_dev_version(self, version: str) -> bool:
        """
        Check if version is development/pre-release
        
        Args:
            version: Version string
            
        Returns:
            True if dev version, False otherwise
        """
        return '.99.' in version or 'rc' in version.lower() or 'beta' in version.lower()
    
    def analyze_risk_level(self, result: Dict) -> str:
        """
        Determine node risk level based on multiple factors
        
        Args:
            result: Node data dictionary
            
        Returns:
            Risk level: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
        """
        risk_factors = []
        
        # CRITICAL: RPC exposed
        if result['port'] == 8332:
            return 'CRITICAL'
        
        # HIGH risk factors
        if self.is_vulnerable_version(result.get('version', '')):
            risk_factors.append('vulnerable_version')
        
        if self.is_dev_version(result.get('version', '')):
            risk_factors.append('dev_version')
        
        # Check for multiple high-risk services
        enrichment = result.get('enrichment', {})
        if enrichment:
            ports = enrichment.get('all_ports', [])
            high_risk_exposed = [p for p in ports if p in self.config.HIGH_RISK_PORTS]
            if len(high_risk_exposed) > 2:
                risk_factors.append('multiple_services')
        
        # Determine level
        if len(risk_factors) >= 2:
            return 'HIGH'
        elif len(risk_factors) == 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_risk_reason(self, result: Dict, risk_level: str) -> str:
        """
        Get human-readable reason for risk level
        
        Args:
            result: Node data dictionary
            risk_level: Assigned risk level
            
        Returns:
            Comma-separated string of risk factors
        """
        reasons = []
        
        if result['port'] == 8332:
            reasons.append("RPC_EXPOSED")
        
        if self.is_vulnerable_version(result.get('version', '')):
            version = result.get('version', '')
            # Try to find specific CVE
            for vuln_ver, cve in self.config.VULNERABLE_VERSIONS.items():
                if vuln_ver in version:
                    reasons.append(f"VULNERABLE_VERSION({cve})")
                    break
            else:
                reasons.append("VULNERABLE_VERSION")
        
        if self.is_dev_version(result.get('version', '')):
            reasons.append("DEV_VERSION")
        
        enrichment = result.get('enrichment', {})
        if enrichment:
            ports = enrichment.get('all_ports', [])
            high_risk_exposed = [p for p in ports if p in self.config.HIGH_RISK_PORTS]
            if len(high_risk_exposed) > 2:
                service_names = [self.config.HIGH_RISK_PORTS[p] for p in high_risk_exposed[:3]]
                reasons.append(f"MULTIPLE_SERVICES({', '.join(service_names)})")
        
        return ', '.join(reasons) if reasons else 'LOW_RISK'
    
    def extract_version_from_banner(self, result: Dict) -> str:
        """
        Extract version information from banner or product fields
        
        Args:
            result: Node data dictionary
            
        Returns:
            Version string or 'Unknown'
        """
        banner = result.get('banner', '')
        product = result.get('product', '')
        version = result.get('version', '')
        
        # Try banner first
        if '/Satoshi:' in banner:
            try:
                version_part = banner.split('/Satoshi:')[1].split('/')[0]
                return f"Satoshi:{version_part}"
            except (IndexError, ValueError):
                pass
        
        # Try product + version
        if product and version:
            return f"{product}:{version}"
        
        # Fallback to version only
        return version or 'Unknown'
    
    def generate_statistics(self, results: List[Dict]) -> Dict:
        """
        Generate comprehensive statistics from scan results
        
        Args:
            results: List of node data dictionaries
            
        Returns:
            Statistics dictionary
        """
        stats = {
            'total_results': len(results),
            'unique_ips': len(set(r['ip'] for r in results)),
        }
        
        # Port distribution
        port_dist = Counter(r['port'] for r in results)
        stats['port_distribution'] = dict(port_dist)
        
        # Country distribution
        country_dist = Counter(r['country_code'] for r in results if r['country_code'])
        stats['country_distribution'] = dict(country_dist.most_common(20))
        
        # Version distribution
        version_dist = Counter()
        for r in results:
            version = self.extract_version_from_banner(r)
            if version:
                version_dist[version] += 1
        stats['version_distribution'] = dict(version_dist.most_common(50))
        
        # ASN distribution
        asn_dist = Counter(r['asn'] for r in results if r['asn'])
        stats['asn_distribution'] = dict(asn_dist.most_common(20))
        
        # Risk distribution
        risk_dist = Counter()
        for r in results:
            risk = self.analyze_risk_level(r)
            risk_dist[risk] += 1
        stats['risk_distribution'] = dict(risk_dist)
        
        # Vulnerable nodes count
        vulnerable_count = sum(
            1 for r in results 
            if self.is_vulnerable_version(r.get('version', ''))
        )
        stats['vulnerable_nodes'] = vulnerable_count
        
        # RPC exposed count
        rpc_exposed = sum(1 for r in results if r['port'] == 8332)
        stats['rpc_exposed'] = rpc_exposed
        
        # Development versions count
        dev_versions = sum(
            1 for r in results
            if self.is_dev_version(r.get('version', ''))
        )
        stats['dev_versions'] = dev_versions
        
        return stats
    
    def identify_critical_nodes(self, results: List[Dict]) -> List[Dict]:
        """
        Identify and format critical/high-risk nodes
        
        Args:
            results: List of node data dictionaries
            
        Returns:
            List of critical node dictionaries
        """
        critical_nodes = []
        
        for result in results:
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
        
        # Sort by risk level (CRITICAL first, then HIGH)
        critical_nodes.sort(
            key=lambda x: (x['risk_level'] == 'CRITICAL', x['risk_level'] == 'HIGH'),
            reverse=True
        )
        
        return critical_nodes
    
    def get_vulnerability_details(self, version: str) -> Dict:
        """
        Get detailed vulnerability information for a version
        
        Args:
            version: Version string
            
        Returns:
            Dictionary with vulnerability details
        """
        details = {
            'is_vulnerable': self.is_vulnerable_version(version),
            'is_dev': self.is_dev_version(version),
            'cves': [],
            'severity': 'UNKNOWN',
        }
        
        # Find matching CVEs
        for vuln_ver, cve_info in self.config.VULNERABLE_VERSIONS.items():
            if vuln_ver in version:
                details['cves'].append(cve_info)
                
                # Determine severity
                if 'inflation' in cve_info.lower() or 'consensus' in cve_info.lower():
                    details['severity'] = 'CRITICAL'
                elif 'remote' in cve_info.lower() or 'crash' in cve_info.lower():
                    details['severity'] = 'HIGH'
                else:
                    details['severity'] = 'MEDIUM'
        
        return details
