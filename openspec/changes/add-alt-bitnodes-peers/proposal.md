## Why

`--ips` mode scans node IPs we already know about instead of relying on what Shodan's search happens to index. Today those lists come from peer-observer exports or a hand-converted `getnodeaddresses`. Our own crawler, **alt-bitnodes** (`https://pesquisa.hacknodes.xyz`, repo `ifuensan/alt-bitnodes`), publishes a snapshot of every *reachable* node about every 40 minutes — a richer, continuously refreshed source (~2,700 nodes per snapshot, ~1,100 of them IPv6; the 8-day union is ~6,700 distinct addresses). The crawler currently reaches clearnet only (its `/api/v1/stats/window` reports 0 Tor and 0 I2P).

Feeding a snapshot straight into `--ips` is unsafe: alt-bitnodes keys IPv6 nodes **without brackets** (`2a07:9a07:3::2:105:8333`). That string is itself a valid IPv6 address, so the generic reader takes it as an IP with no port and silently looks up a non-existent address — about 42% of the snapshot would be wrong without any error. The source needs a format-aware converter. A single snapshot also misses nodes that are only intermittently reachable, so the useful list is the **union of the last 8 days**, refreshed once a day.

## What Changes

- **New package `src/peers/`** for peer-list sources, starting with `alt_bitnodes.py`:
  - Lists snapshots via `GET /api/v1/snapshots/` (paginated) and downloads each one in the window via `GET /api/v1/snapshots/<ts>/`.
  - Parses node keys by the known `host:port` format (split on the last `:`), validates the IP, drops `.onion` / `.i2p`, CJDNS (`fc00::/8`), non-globally-routable and invalid entries (none of which Shodan can look up), and brackets IPv6 on output.
  - **Incremental cache**: each snapshot's address list is stored once under `data/peers/alt-bitnodes/cache/<ts>.txt`; a daily run only downloads snapshots it doesn't have (~37/day, ~7 MB) and prunes entries older than the window. The first run fetches the whole window (~300 snapshots, ~57 MB transfer).
  - Writes the union to `data/peers/alt-bitnodes.txt` (one `host:port` per line, header comments with source, window and snapshot count), ready for `--ips`.
- **New CLI** `python -m src.peers.fetch alt-bitnodes [--days N] [--output PATH]`, printing a summary (snapshots cached/downloaded/failed, unique IPs by family) and the follow-up scan command.
- **Config**: `ALT_BITNODES_URL` (default `https://pesquisa.hacknodes.xyz`), `ALT_BITNODES_WINDOW_DAYS` (default `8`).
- All files are written through `src/safe_paths.py` (under `INPUT_DIR`).
- **Docs**: `docs/bitcoin-scanner.md`, `CLAUDE.md`, `.env.example`; `docs/ARCHITECTURE.md` gains the source.

The recommended daily flow:

```
python -m src.peers.fetch alt-bitnodes
python -m src.scanner --ips data/peers/alt-bitnodes.txt --source-tag alt-bitnodes
python -m src.db.cli db-import output/raw_data/nodes_<ts>.json
```

## Capabilities

### New Capabilities
- `peer-sources`: fetching node address lists from external crawlers into `--ips`-ready files, starting with alt-bitnodes (windowed union, incremental cache, format-aware parsing).

### Modified Capabilities
<!-- none: the scanner, the --ips reader and the importer are unchanged -->

## Impact

- **New code**: `src/peers/__init__.py`, `src/peers/alt_bitnodes.py`, `src/peers/fetch.py`; tests with mocked HTTP.
- **Unchanged**: `src/scanner.py`, `src/ip_list.py`, importer, database schema, API, dashboard.
- **External**: read-only GETs to our own alt-bitnodes instance (served behind CloudFront); a short delay between snapshot downloads keeps the load gentle.
- **Out of scope**: scheduling the daily run (systemd timer / cron on frodo — follow-up with deployment); using the snapshot's user-agent / height / services metadata; onion/I2P nodes (Shodan can't look them up); auto-chaining fetch → scan → import.
