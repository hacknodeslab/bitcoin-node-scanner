## Why

Surveillance companies likely operate clusters of public Electrum servers under different identities to silently harvest user wallet addresses and correlate them with IPs. Because these operators share Bitcoin Core backends across their frontends, they produce detectable behavioral correlations — block notification timing, fee histograms, downtime windows — that can be measured and clustered to expose sybil groups.

## What Changes

- New standalone module `electrum_monitor.py` (M0 prototype): a single-file asyncio daemon that connects to a hardcoded list of public Electrum servers, collects behavioral fingerprints continuously, and stores them in SQLite
- New SQLite schema for time-series storage of block notifications, server metadata, fee data, availability events
- CLI interface with `--report` and `--dump-blocks` flags
- Graceful shutdown on Ctrl+C with connection cleanup

## Capabilities

### New Capabilities

- `server-discovery`: Maintain a registry of known Electrum servers (seed list for M0; IRC + peer scraping in M1+)
- `data-collection-daemon`: Long-running asyncio process that subscribes to block headers, polls fee data, records RTT, and logs uptime events per server
- `sqlite-storage`: Schema and write layer for all collected time-series data
- `cli-reporting`: `--report` summary and `--dump-blocks` CSV export

### Modified Capabilities

(none — this is a new standalone module)

## Impact

- New file: `electrum_monitor.py` at project root (self-contained, stdlib only)
- New file: `electrum_monitor.db` (SQLite, gitignored)
- No changes to existing `src/` web or scanner code
- No new pip dependencies for M0
