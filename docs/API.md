# API Reference

## Table of Contents

- [Overview](#overview)
- [Core Classes](#core-classes)
- [Configuration](#configuration)
- [Main Methods](#main-methods)
- [Data Structures](#data-structures)
- [Examples](#examples)

---

## Overview

The Bitcoin Node Scanner provides a Python API for programmatic access to node scanning capabilities. This document describes the classes, methods, and data structures available.

## Core Classes

### BitcoinNodeScanner

Main scanner class that orchestrates the entire scanning process.

```python
from scanner import BitcoinNodeScanner

scanner = BitcoinNodeScanner(api_key="your_shodan_key")
scanner.run_full_scan(max_per_query=1000, enrich=True)
```

#### Constructor

```python
BitcoinNodeScanner(api_key: str = None)
```

**Parameters:**
- `api_key` (str, optional): Shodan API key. Defaults to `SHODAN_API_KEY` environment variable.

**Raises:**
- `ValueError`: If no API key is provided or configured.

---

## Configuration

### Config Class

Static configuration class containing all scanner settings.

```python
from scanner import Config

# Access configuration values
queries = Config.QUERIES
vulnerable_versions = Config.VULNERABLE_VERSIONS
bitcoin_ports = Config.BITCOIN_PORTS
```

#### Configuration Attributes

**SHODAN_API_KEY** (str)
- Shodan API key from environment variable

**QUERIES** (List[str])
- List of Shodan search queries to execute
- Default queries include: `'product:Bitcoin'`, `'port:8333'`, etc.

**BITCOIN_PORTS** (Dict[int, str])
- Mapping of Bitcoin-related ports to descriptions
- Example: `{8333: 'P2P Mainnet', 8332: 'RPC Mainnet (CRITICAL)'}`

**HIGH_RISK_PORTS** (Dict[int, str])
- Mapping of high-risk service ports
- Example: `{22: 'SSH', 3306: 'MySQL'}`

**VULNERABLE_VERSIONS** (Dict[str, str])
- Known vulnerable Bitcoin versions
- Example: `{'0.18.0': 'Multiple CVEs'}`

**Output Directories:**
- `OUTPUT_DIR`: Base output directory (`'output'`)
- `RAW_DATA_DIR`: Raw data storage (`'output/raw_data'`)
- `REPORTS_DIR`: Reports storage (`'output/reports'`)
- `LOGS_DIR`: Log files storage (`'output/logs'`)

---

## Main Methods

### Account Management

#### get_account_info()

Retrieves Shodan account information and available credits.

```python
info = scanner.get_account_info()
print(f"Query credits: {info.get('query_credits')}")
```

**Returns:**
- `Dict`: Shodan account information
- `None`: If error occurs

---

### Scanning Methods

#### search_bitcoin_nodes()

Search for Bitcoin nodes using a specific query.

```python
results = scanner.search_bitcoin_nodes(
    query="port:8333",
    max_results=1000
)
```

**Parameters:**
- `query` (str): Shodan search query
- `max_results` (int): Maximum number of results to retrieve

**Returns:**
- `List[Dict]`: List of node data dictionaries

---

#### scan_all_queries()

Execute all configured queries.

```python
scanner.scan_all_queries(max_per_query=1000)
```

**Parameters:**
- `max_per_query` (int): Maximum results per individual query

**Side Effects:**
- Populates `scanner.results` with all findings
- Updates `scanner.unique_ips` with discovered IP addresses

---

### Enrichment Methods

#### enrich_with_host_scan()

Retrieve complete host information for a specific IP.

```python
host_data = scanner.enrich_with_host_scan(ip="192.168.1.1")
```

**Parameters:**
- `ip` (str): IP address to scan

**Returns:**
- `Dict`: Complete host information including:
  - `all_ports`: List of exposed ports
  - `all_services`: List of service details
  - `tags`: Shodan tags
  - `vulns`: Known vulnerabilities
  - `os`: Operating system
  - `last_update`: Last update timestamp

---

#### enrich_critical_nodes()

Enrich critical nodes with full host scans.

```python
scanner.enrich_critical_nodes(max_enrichments=100)
```

**Parameters:**
- `max_enrichments` (int): Maximum number of nodes to enrich

**Side Effects:**
- Updates `scanner.results` with enrichment data for critical nodes

---

### Analysis Methods

#### is_vulnerable_version()

Check if a version string matches known vulnerable versions.

```python
is_vuln = scanner.is_vulnerable_version("Satoshi:0.18.0")
# Returns: True
```

**Parameters:**
- `version` (str): Version string to check

**Returns:**
- `bool`: True if vulnerable, False otherwise

---

#### analyze_risk_level()

Determine risk level for a node result.

```python
risk = scanner.analyze_risk_level(node_result)
# Returns: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
```

**Parameters:**
- `result` (Dict): Node data dictionary

**Returns:**
- `str`: Risk level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

**Risk Criteria:**
- **CRITICAL**: RPC port (8332) exposed
- **HIGH**: 2+ risk factors (vulnerable version, dev version, multiple services)
- **MEDIUM**: 1 risk factor
- **LOW**: No risk factors

---

#### extract_version_from_banner()

Extract version information from banner or product fields.

```python
version = scanner.extract_version_from_banner(node_result)
# Returns: "Satoshi:29.2.0" or "Unknown"
```

**Parameters:**
- `result` (Dict): Node data dictionary

**Returns:**
- `str`: Extracted version string or 'Unknown'

---

### Statistics Methods

#### generate_statistics()

Generate comprehensive statistics from scan results.

```python
stats = scanner.generate_statistics()
```

**Returns:**
- `Dict`: Statistics dictionary containing:
  - `total_results`: Total nodes found
  - `unique_ips`: Count of unique IP addresses
  - `port_distribution`: Counter of ports
  - `country_distribution`: Top 20 countries
  - `version_distribution`: Top 50 versions
  - `asn_distribution`: Top 20 ASNs
  - `risk_distribution`: Distribution by risk level
  - `vulnerable_nodes`: Count of vulnerable nodes
  - `rpc_exposed`: Count of exposed RPC interfaces

---

### Output Methods

#### save_raw_data()

Save raw scan results to JSON and CSV.

```python
scanner.save_raw_data()
```

**Outputs:**
- `output/raw_data/nodes_{timestamp}.json`
- `output/raw_data/nodes_{timestamp}.csv`

---

#### save_statistics()

Save statistics to JSON file.

```python
scanner.save_statistics(stats)
```

**Parameters:**
- `stats` (Dict): Statistics dictionary

**Outputs:**
- `output/reports/statistics_{timestamp}.json`

---

#### generate_report()

Generate and save human-readable text report.

```python
scanner.generate_report(stats)
```

**Parameters:**
- `stats` (Dict): Statistics dictionary

**Outputs:**
- `output/reports/report_{timestamp}.txt`
- Console output

---

#### generate_critical_nodes_list()

Generate list of critical/high-risk nodes.

```python
critical_nodes = scanner.generate_critical_nodes_list()
```

**Returns:**
- `List[Dict]`: List of critical node dictionaries

**Outputs:**
- `output/reports/critical_nodes_{timestamp}.json`
- `output/reports/critical_nodes_{timestamp}.csv`

---

### Orchestration Methods

#### run_full_scan()

Execute complete scan workflow.

```python
scanner.run_full_scan(
    max_per_query=1000,
    enrich=True
)
```

**Parameters:**
- `max_per_query` (int): Maximum results per query
- `enrich` (bool): Whether to enrich critical nodes

**Workflow:**
1. Check account info
2. Execute all queries
3. Enrich critical nodes (if enabled)
4. Generate statistics
5. Save all outputs

---

## Data Structures

### Node Result Dictionary

Structure of individual node data:

```python
{
    'timestamp': str,           # Scan timestamp
    'query': str,               # Query that found this node
    'ip': str,                  # IP address
    'port': int,                # Port number
    'transport': str,           # Transport protocol ('tcp'/'udp')
    'product': str,             # Product name
    'version': str,             # Version string
    'banner': str,              # Full banner text
    'organization': str,        # Organization/ISP
    'isp': str,                 # ISP name
    'asn': str,                 # Autonomous System Number
    'country': str,             # Country name
    'country_code': str,        # ISO country code
    'city': str,                # City name
    'hostnames': List[str],     # Associated hostnames
    'domains': List[str],       # Associated domains
    'timestamp_shodan': str,    # Shodan scan timestamp
    'ssl': Dict,                # SSL/TLS information
    'vulns': List[str],         # Known vulnerabilities
    'cpe': List[str],           # CPE identifiers
    'enrichment': Dict          # Optional: Full host data
}
```

### SSL Information Dictionary

```python
{
    'enabled': bool,
    'version': str,
    'cipher': str,
    'cert_issued': str,
    'cert_expires': str,
    'cert_subject': Dict
}
```

### Enrichment Dictionary

```python
{
    'all_ports': List[int],
    'all_services': List[Dict],
    'tags': List[str],
    'vulns': List[str],
    'os': str,
    'last_update': str
}
```

### Critical Node Dictionary

```python
{
    'ip': str,
    'port': int,
    'version': str,
    'risk_level': str,          # 'CRITICAL' or 'HIGH'
    'country': str,
    'organization': str,
    'asn': str,
    'reason': str               # Comma-separated risk factors
}
```

---

## Examples

### Basic Scan

```python
from scanner import BitcoinNodeScanner

# Initialize scanner
scanner = BitcoinNodeScanner(api_key="your_api_key")

# Run scan
scanner.run_full_scan(max_per_query=500, enrich=False)
```

### Custom Query Scan

```python
scanner = BitcoinNodeScanner()

# Search specific query
results = scanner.search_bitcoin_nodes(
    query='port:8332',  # RPC port only
    max_results=100
)

# Analyze results
for node in results:
    risk = scanner.analyze_risk_level(node)
    if risk == 'CRITICAL':
        print(f"CRITICAL: {node['ip']}:{node['port']}")
```

### Targeted Enrichment

```python
scanner = BitcoinNodeScanner()
scanner.scan_all_queries(max_per_query=1000)

# Find vulnerable nodes
vulnerable_ips = [
    r['ip'] for r in scanner.results 
    if scanner.is_vulnerable_version(r.get('version', ''))
]

# Enrich only vulnerable nodes
for ip in vulnerable_ips[:50]:
    enrichment = scanner.enrich_with_host_scan(ip)
    print(f"{ip}: {enrichment.get('all_ports', [])}")
```

### Statistics Analysis

```python
scanner = BitcoinNodeScanner()
scanner.scan_all_queries()

# Generate stats
stats = scanner.generate_statistics()

# Analyze distribution
print(f"Total nodes: {stats['total_results']}")
print(f"Vulnerable: {stats['vulnerable_nodes']}")
print(f"RPC exposed: {stats['rpc_exposed']}")

# Top countries
for country, count in list(stats['country_distribution'].items())[:5]:
    print(f"{country}: {count}")
```

### Custom Risk Analysis

```python
scanner = BitcoinNodeScanner()
scanner.scan_all_queries()

# Custom risk filtering
high_value_targets = []

for result in scanner.results:
    # Custom criteria
    if (result['port'] == 8332 or 
        scanner.is_vulnerable_version(result.get('version', '')) and
        result['country_code'] == 'US'):
        
        high_value_targets.append({
            'ip': result['ip'],
            'version': scanner.extract_version_from_banner(result),
            'org': result['organization']
        })

print(f"High-value targets: {len(high_value_targets)}")
```

### Export Custom Format

```python
import json

scanner = BitcoinNodeScanner()
scanner.run_full_scan()

# Custom export
export_data = {
    'scan_date': scanner.timestamp,
    'critical_nodes': [
        {
            'ip': r['ip'],
            'port': r['port'],
            'version': scanner.extract_version_from_banner(r),
            'risk': scanner.analyze_risk_level(r)
        }
        for r in scanner.results
        if scanner.analyze_risk_level(r) == 'CRITICAL'
    ]
}

with open('custom_export.json', 'w') as f:
    json.dump(export_data, f, indent=2)
```

---

## Error Handling

### Common Exceptions

```python
from scanner import BitcoinNodeScanner
import shodan

try:
    scanner = BitcoinNodeScanner(api_key="invalid_key")
    scanner.run_full_scan()
    
except ValueError as e:
    print(f"Configuration error: {e}")
    
except shodan.APIError as e:
    print(f"Shodan API error: {e}")
    
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Rate Limiting

The scanner includes built-in rate limiting:
- 1 second between individual requests
- 2 seconds between different queries
- Automatic pagination with delay

To handle rate limit errors:

```python
scanner = BitcoinNodeScanner()

try:
    scanner.scan_all_queries(max_per_query=5000)
except shodan.APIError as e:
    if 'rate limit' in str(e).lower():
        print("Rate limit reached. Reduce max_per_query or upgrade API plan")
```

---

## Logging

### Access Logs

```python
scanner = BitcoinNodeScanner()
scanner.run_full_scan()

# Log file location
print(f"Log file: {scanner.log_file}")
# Output: output/logs/scan_20260103_153045.log
```

### Log Levels

The scanner logs at INFO level by default:
- `INFO`: Normal operations
- `WARNING`: Non-critical issues
- `ERROR`: Critical failures

### Custom Logging

```python
scanner = BitcoinNodeScanner()

# Manual logging
scanner.log("Custom message", level='INFO')
scanner.log("Warning message", level='WARNING')
scanner.log("Error occurred", level='ERROR')
```

---

## Best Practices

### Memory Management

For large scans, process results incrementally:

```python
scanner = BitcoinNodeScanner()

# Scan in batches
for query in Config.QUERIES:
    results = scanner.search_bitcoin_nodes(query, max_results=500)
    
    # Process batch
    for result in results:
        risk = scanner.analyze_risk_level(result)
        if risk in ['CRITICAL', 'HIGH']:
            # Handle critical node
            pass
    
    # Clear batch
    results = []
```

### API Credit Conservation

```python
scanner = BitcoinNodeScanner()

# Check credits first
info = scanner.get_account_info()
credits = info.get('query_credits', 0)

if credits < 100:
    print("Low credits, running minimal scan")
    scanner.run_full_scan(max_per_query=100, enrich=False)
else:
    scanner.run_full_scan(max_per_query=1000, enrich=True)
```

### Parallel Processing

For advanced users:

```python
from concurrent.futures import ThreadPoolExecutor

scanner = BitcoinNodeScanner()
scanner.scan_all_queries()

# Parallel enrichment
critical_ips = [r['ip'] for r in scanner.results if r['port'] == 8332]

with ThreadPoolExecutor(max_workers=5) as executor:
    enrichments = executor.map(scanner.enrich_with_host_scan, critical_ips[:50])
```

---

## Version History

- **v1.0.0** (2026-01-03): Initial release

---

## Support

For API questions or issues:
- GitHub Issues: https://github.com/hacknodes-lab/bitcoin-node-scanner/issues
- Email: security@hacknodes.com
- Documentation: https://github.com/hacknodes-lab/bitcoin-node-scanner/docs

