# Usage Guide

## Basic Usage

### Quick Scan
```bash
# Run default scan
python src/scanner.py

# Or use quick scan script
./scripts/quick_scan.sh
```

### Check Shodan Credits
```bash
python src/scanner.py --check-credits
```

## Advanced Usage

### Custom Number of Results
```bash
# Scan with 2000 results per query
python src/scanner.py --max-per-query 2000
```

### Disable Host Enrichment
```bash
# Skip enrichment to save API credits
python src/scanner.py --no-enrich
```

### Custom API Key
```bash
# Use specific API key
python src/scanner.py --api-key YOUR_API_KEY
```

## Output Files

After a scan, you'll find:
```
output/
├── raw_data/
│   ├── nodes_20260103_153045.json    # All node data in JSON
│   └── nodes_20260103_153045.csv     # All node data in CSV
├── reports/
│   ├── statistics_20260103_153045.json        # Statistics
│   ├── report_20260103_153045.txt             # Human-readable report
│   ├── critical_nodes_20260103_153045.json    # Critical nodes only
│   └── critical_nodes_20260103_153045.csv     # Critical nodes CSV
└── logs/
    └── scan_20260103_153045.log      # Scan log
```

## Understanding Results

### Risk Levels

- **CRITICAL**: RPC interface publicly exposed
- **HIGH**: Vulnerable version or multiple high-risk services
- **MEDIUM**: Development version or outdated version
- **LOW**: Recent version with secure configuration

### Key Metrics

- **Total nodes found**: Total results from all queries
- **Unique IPs**: Deduplicated IP addresses
- **Vulnerable nodes**: Nodes running known vulnerable versions
- **RPC exposed**: Critical security issue - immediate action required

## Example Workflow
```bash
# 1. Check your API credits
python src/scanner.py --check-credits

# 2. Run a quick scan without enrichment
python src/scanner.py --max-per-query 500 --no-enrich

# 3. Review the report
cat output/reports/report_*.txt

# 4. Check critical nodes
cat output/reports/critical_nodes_*.csv

# 5. Run full scan with enrichment
python src/scanner.py --max-per-query 1000
```

## Tips

- Start with `--no-enrich` to conserve API credits
- Use `--max-per-query 100` for testing
- Review logs in `output/logs/` if issues occur
- Critical nodes list is in both JSON and CSV formats
