## Why

Shodan search queries only surface Bitcoin nodes Shodan happened to index, which misses most of the live P2P network (non-listening hosts, hosts behind NAT, or simply hosts Shodan never visited on a Bitcoin port). Operators who run a node — e.g. b10c's peer-observer on a pruned node — already have a large list of real peer IPs. Feeding that list into Shodan host lookups lets us assess far more of the actual network than query-based discovery alone.

## What Changes

- Add a **scan-by-IP-list** mode to the scanner: `python -m src.scanner --ips <file>`.
- Read a tolerant input file in peer-observer's `host:port` format — IPv4 as `1.2.3.4:8333` and IPv6 bracketed as `[2001:db8::1]:8333` — and also accept a plain "one IP per line" file or a CSV `ip,port`. Skip blank lines and `#` comments; deduplicate IPs.
- For each unique IP, perform a Shodan **host lookup** (`api.host(ip)`) and map every Bitcoin-relevant service banner through the existing node-parsing path, so records are identical to query-based scans. Host lookups (`/shodan/host/{ip}`) consume **no query credits and no scan credits** — the only practical limit is the API rate limit (~1 req/s).
- Pace requests to respect the Shodan rate limit and accept an optional `--max-ips` cap to bound a run; the default query-credit ceiling does not apply (host lookups don't spend credits).
- IPs not present in Shodan are **skipped** (host-lookup only — no on-demand active scanning) and counted.
- Write a JSON dump to `output/` exactly like the normal scanner; the operator loads it with the existing `db-import` (no direct DB writes, no new import command).
- Print a run summary: total IPs read, unique, found in Shodan, skipped (not found), and elapsed time / lookups performed.

## Capabilities

### New Capabilities
- `ip-list-scan`: Scan a caller-provided list of node IPs via Shodan host lookups (tolerant `host:port`/text input, dedup, per-IP lookup, Bitcoin-service mapping, rate-limit paced with an optional run cap, JSON output, skip-not-found).

### Modified Capabilities
<!-- None: scanner-credit-safety is reused as-is (no requirement change); produced records are ordinary nodes already covered by database-storage and the node-list views. -->

## Impact

- **Code**: `src/scanner.py` (new `--ips` CLI flag + IP-list scan flow reusing `parse_node_data`, `SecurityAnalyzer`, GeoIP, credit tracking and the JSON reporter). A small input-reader helper for the `host:port` / text format (IPv4 and bracketed IPv6).
- **Shodan usage**: host lookups consume **no query credits and no scan credits**; the run is bounded by the API rate limit (~1 req/s → ~3.5 h for ~12.7k IPs) and an optional `--max-ips` cap. The plan's "results/month" (query credits) and "scan IPs/month" (scan credits) quotas are not touched by this mode.
- **Downstream**: none new — output is a standard scanner JSON dump consumed by `db-import`; records appear in the existing node list / stats / vulnerability views.
- **Docs**: `README.md` / `docs/bitcoin-scanner.md` and `CLAUDE.md` gain the `--ips` flow.
- **Out of scope**: on-demand active scanning (`api.scan` / scan credits), parsing peer-observer's native/Prometheus format directly, and any new dashboard UI.
