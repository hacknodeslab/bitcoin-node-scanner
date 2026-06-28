## Context

`src/scanner.py` discovers nodes through Shodan **search** queries (`api.search`), where each result page costs one query credit. It already wraps `api.host(ip)` in `enrich_with_host_scan`, but only to enrich already-discovered "critical" nodes, and it returns a partial shape — there is no path to scan a caller-supplied IP list.

The supporting machinery already exists and should be reused unchanged:
- `parse_node_data(result, query)` maps a Shodan banner dict → the canonical node record.
- `SecurityAnalyzer` (analyzer.py) assigns risk; `geoip.py` enriches geo; `reporter.py` writes the JSON dump.
- `credit_tracker.py` + `MAX_QUERY_CREDITS_PER_SCAN` bound query-credit spend for the **search**-based mode. Note: Shodan host lookups (`/shodan/host/{ip}`) consume **no query credits and no scan credits**, so that ceiling is irrelevant to IP-list mode — the binding constraint there is the API rate limit (~1 req/s).
- Convention (CLAUDE.md): the scanner writes JSON to `output/` and does **not** persist; the operator runs `db-import`.

The operator's IP source is b10c's peer-observer, exported to clearnet host lists in `host:port` form — IPv4 as `1.2.3.4:8333` and IPv6 bracketed as `[2001:db8::1]:8333` (two files: `peerobserverclearnetipv4.txt`, `peerobserverclearnetipv6.txt`, ~12.7k hosts total). `bitcoin-cli getnodeaddresses` is an equivalent alternative source.

## Goals / Non-Goals

**Goals:**
- Add `python -m src.scanner --ips <file>` that looks each provided IP up in Shodan and produces a standard scanner JSON dump.
- Reuse `parse_node_data` so IP-list records are byte-for-byte equivalent to query-discovered records (same DB import path, same dashboard).
- Be tolerant of input format: peer-observer `host:port` (IPv4 and bracketed IPv6), plus plain IP-per-line and CSV `ip[,port]`; comments; dedup.
- Pace lookups to respect the Shodan API rate limit and accept an optional `--max-ips` cap to bound a run.
- Skip IPs not in Shodan and count them.

**Non-Goals:**
- On-demand active scanning (`api.scan` / scan credits).
- Parsing peer-observer's NATS/protobuf event stream directly — we ingest the flat `host:port` text files the operator exports.
- New persistence path or dashboard UI (records are ordinary nodes).

## Decisions

### 1. Host lookup, not search
Use `api.host(ip)` per IP. **Why:** search can't target an arbitrary large IP list efficiently (`net:` only covers CIDRs). Host lookup returns Shodan's cached data for exactly that IP and — per the Shodan API docs — consumes **no query credits**. Alternative (on-demand `api.scan`) was rejected: it costs scan credits, is asynchronous, and is out of scope.

### 2. Map `host['data']` through `parse_node_data`
`api.host(ip)` returns a host dict whose `data` is a list of per-service banners; each banner has the same fields (`ip_str`, `port`, `product`, `version`, `data`, `location`, `asn`, `org`, …) that `parse_node_data` already consumes. Iterate `host['data']`, keep Bitcoin-relevant services, and feed each through `parse_node_data` with a synthetic `query` label (e.g. `ip-list:<source-file>`) so provenance is visible. **Why:** zero divergence from the query path; the analyzer/geoip/reporter/db-import all work unchanged.

### 3. Bitcoin-service selection
Keep services whose port is in the known Bitcoin set (mainnet/testnet/signet P2P + RPC: 8333, 8332, 18333, 18332, 38333, 38332, plus any port supplied for that IP in the input). **Why:** an IP may run unrelated services Shodan also indexed; we only want Bitcoin endpoints. If the input supplies a port (peer-observer always does), treat it as authoritative for that IP and always include a matching banner. If a looked-up IP has Bitcoin services Shodan saw on other ports, include those too. Note peer-observer also lists non-default P2P ports (e.g. `9333`), which the supplied-port rule preserves.

### 4. Run safety via rate-limit pacing and an optional cap
Host lookups are credit-free, so the `MAX_QUERY_CREDITS_PER_SCAN` ceiling would never trip and is not the right guard. Instead: pace lookups to the Shodan rate limit (~1 req/s; configurable via a `--rate`/sleep) and accept an optional `--max-ips N` to bound a single run (resume by slicing the file). Use `credit_tracker`/`api.info()` only to *report* account state, not to gate. **Why:** the real constraints are wall-clock time and the API rate limit, not credits; an explicit cap gives the operator a clean stop without a misleading credit concept. Alternative (gate on query credits) rejected as factually inapplicable.

### 5. Tolerant input reader
A small helper parses each non-blank, non-`#` line into `(ip, port?)`, handling, in order: bracketed IPv6 `[2001:db8::1]:8333` (peer-observer IPv6); IPv4 `host:port` `1.2.3.4:8333` (peer-observer IPv4); CSV `ip,port`; and a bare IP (v4 or v6) with no port. It splits the port off carefully so a bare unbracketed IPv6 address (which also contains colons) is not mistaken for `host:port`. Each IP is validated with `ipaddress`; dedupe is by IP, merging a later port for an already-seen IP as an extra expected port. **Why:** match peer-observer's actual `host:port` output while staying tolerant of plain lists and CSV; bracket/colon handling is the one subtlety worth getting right.

### 6. Output unchanged
Write the same JSON dump shape the normal scanner writes, to `output/`, then the operator runs `db-import`. **Why:** preserves the "scanner writes JSON, db-import persists" convention; no new import command, no schema change.

## Risks / Trade-offs

- **Most P2P IPs aren't in Shodan** → host lookups 404. *Mitigation:* skip + count; the summary makes the hit-rate explicit so the operator understands coverage. (Closing this gap needs on-demand scan — a deliberate non-goal.)
- **Wall-clock time on large lists** (rate-limited to ~1 req/s, ~12.7k IPs ≈ 3.5 h) → *Mitigation:* run unattended; support an optional `--max-ips` cap and resume-by-slicing so a run can be bounded or split. No credit cost, so no budget exhaustion. Document the time expectation.
- **`api.host` shape vs. `parse_node_data` expectations** — host banners are per-service and should match, but top-level fields (`asn`, `org`) sometimes live on the host root rather than each banner. *Mitigation:* fall back to host-root fields when a banner omits them; cover with a unit test using a recorded `api.host` fixture.
- **Stale Shodan data** — host lookups return cached results that may predate the node's current state. *Mitigation:* `last_update`/`timestamp_shodan` is already captured per record; out of scope to refresh.

## Open Questions

- Resolved: peer-observer exports `host:port` per line (IPv4 `1.2.3.4:8333`, IPv6 `[2001:db8::1]:8333`), split across `peerobserverclearnetipv4.txt` / `peerobserverclearnetipv6.txt`. The reader handles both; the operator can pass either file (or a concatenation).
- Resolved: host lookups are credit-free (Shodan API docs) and the "IP lookups" feature is included from the one-time **Membership** tier upward, so a full ~12.7k-host run costs 0 query/scan credits and does not touch Membership's 100 query / 100 scan monthly quotas. The cost is time: ~3.5 h at ~1 req/s. The `--max-ips` cap and file slicing let the operator bound or split runs. (Note: on Membership the search-based discovery mode is heavily limited — 100 query credits, 20 search pages, no `vuln:`/`tag:` filters — which is exactly why the IP-list path is the cost-effective option on that plan. Shodan's `vulns` field may be absent in host results on lower tiers, but CVEs are derived independently from the NVD catalog.)
