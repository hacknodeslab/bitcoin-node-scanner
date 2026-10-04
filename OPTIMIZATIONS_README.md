# Shodan Credit Optimization

How this project minimizes Shodan API credit usage. All of this lives in
`src/scanner.py` (`OptimizedBitcoinScanner` + `CachedNodeManager`) and
`src/credit_tracker.py` — there is no separate `optimized_scanner.py` module.

## Features

- **Optimized queries**: 5 combined queries instead of 9 naive ones (~44% fewer
  query credits). Configurable via `QUERIES_OPTIMIZED` (env or `config/config.yaml`).
- **Node caching**: results are cached in `cache/nodes_cache.json` (default TTL
  7 days); re-scans only fetch new or changed nodes.
- **Selective enrichment**: only high-risk nodes (exposed RPC, vulnerable
  versions) consume host-enrichment credits.
- **Adaptive pagination**: critical queries (e.g. RPC on port 8332) page deeper
  than normal ones. Hard ceiling via `MAX_QUERY_CREDITS_PER_SCAN` (default 50).
- **Credit tracking**: every scan can be logged and projected against the
  monthly plan (see below).

## Usage

```bash
# Quick scan: cache + enrichment limited to 50 nodes
python -m src.scanner --quick

# Full scan without cache, enrichment capped at 100 nodes (default)
python -m src.scanner --no-cache --max-enrich 100

# Skip enrichment entirely (cheapest)
python -m src.scanner --no-enrich

# Check remaining credits on the account
python -m src.scanner --check-credits

# Credit-free alternative: host lookups from a provided IP list
# (consumes neither query nor scan credits)
python -m src.scanner --ips data/peers/peers.txt
```

Or via the wrapper script (loads `.env` and the venv, then forwards all
arguments to `python -m src.scanner`):

```bash
./scripts/optimized_scan.sh --quick
./scripts/optimized_scan.sh --check-credits
```

## Credit usage tracking

`src/credit_tracker.py` keeps a history of credit consumption and projects
end-of-month usage:

```bash
# View the usage report
python -m src.credit_tracker --report

# Log a scan manually
python -m src.credit_tracker --log --query-credits 5 --scan-credits 50 \
    --type quick --notes "Weekly monitoring scan"
```

`./scripts/optimized_scan.sh` shows the tracker report automatically after a
scan completes.

## Best practices

- Start the month with `--quick` and measure real usage with `--report` before
  increasing frequency.
- Prefer `--ips` with a peer-observer export when you only need known nodes —
  it costs zero credits.
- If projection exceeds ~80% of the monthly plan, lower `--max-enrich` or rely
  more on the cache.
- To force a fresh scan, delete `cache/nodes_cache.json` or pass `--no-cache`.

See [docs/bitcoin-scanner.md](docs/bitcoin-scanner.md) for the full scanner
reference.
