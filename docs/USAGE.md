# Usage Guide

## Basic Usage

### Quick Scan
```bash
# Credit-efficient scan (cache + enrichment limited to 50 nodes)
python -m src.scanner --quick

# Full scan with default settings
python -m src.scanner

# Or use the wrapper scripts
./scripts/quick_scan.sh
./scripts/optimized_scan.sh --quick
```

### Check Shodan Credits
```bash
python -m src.scanner --check-credits
```

## Advanced Usage

### Scan from a provided IP list (`--ips`)

Look up a list of node IPs (e.g. a peer-observer export) via Shodan host
lookups instead of search queries. Host lookups consume **no query or scan
credits**:

```bash
python -m src.scanner --ips data/peers/peers.txt

# Cap the number of lookups and tune the request rate (seconds between calls)
python -m src.scanner --ips peers.txt --max-ips 500 --rate 1
```

Accepted formats: one `host:port` per line, `[ipv6]:port`, or CSV.
`bitcoin-cli getnodeaddresses 0` outputs JSON — convert it first (recipe in
[bitcoin-scanner.md](bitcoin-scanner.md#scan-from-a-provided-ip-list---ips)).
Add `--source-tag <name>` (e.g. `peer-observer`) to tag the imported nodes with
their source; the default tag is `ip-list`.

### Limit Host Enrichment
```bash
# Enrich at most 25 nodes (saves scan credits)
python -m src.scanner --max-enrich 25

# Skip enrichment entirely (cheapest option)
python -m src.scanner --no-enrich
```

### Disable the Node Cache
```bash
# Force a fresh scan, ignoring cached nodes
python -m src.scanner --no-cache
```

### Custom API Key
```bash
# Use a specific API key instead of SHODAN_API_KEY from the environment
python -m src.scanner --api-key YOUR_API_KEY
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
python -m src.scanner --check-credits

# 2. Run a quick scan without enrichment
python -m src.scanner --quick --no-enrich

# 3. Review the report
cat output/reports/report_*.txt

# 4. Check critical nodes
cat output/reports/critical_nodes_*.csv

# 5. Run a full scan with enrichment
python -m src.scanner
```

## Tips

- Start with `--quick` or `--no-enrich` to conserve API credits
- Use `--ips` with a peer list for credit-free scans of known nodes
- Track monthly consumption with `python -m src.credit_tracker --report`
- Review logs in `output/logs/` if issues occur
- Critical nodes list is in both JSON and CSV formats
- See [OPTIMIZATIONS_README.md](../OPTIMIZATIONS_README.md) for credit-saving
  strategies and [bitcoin-scanner.md](bitcoin-scanner.md) for the full reference
