## 1. Input reader

- [x] 1.1 Add an IP-list reader helper (in `src/scanner.py` or a small `src/ip_list.py`) that parses a file into a deduped, ordered list of `(ip, expected_ports)`. Per line, handle: bracketed IPv6 `[2001:db8::1]:8333`, IPv4 `host:port`, CSV `ip,port`, and a bare IP (v4/v6, no port) — taking care not to split an unbracketed IPv6's colons as a port. Skip blank/`#` lines, validate IPs with `ipaddress`, drop invalid lines
- [x] 1.2 Unit tests for the reader: IPv4 `host:port`, bracketed IPv6 `host:port`, non-default port (9333), CSV `ip,port`, bare IPv4/IPv6, comments/blanks ignored, duplicate IPs collapsed (extra ports merged), invalid IP skipped

## 2. Host-lookup scan flow

- [x] 2.1 Add a `scan_from_ip_list(path, max_ips=None)` method that iterates the parsed IPs and calls `api.host(ip)` for each, paced to the Shodan rate limit (~1 req/s, configurable); use `credit_tracker`/`api.info()` only to report account state (host lookups are credit-free)
- [x] 2.2 Map each Shodan host result into node records: iterate `host['data']`, keep Bitcoin-relevant services (known Bitcoin ports + any caller-supplied port for that IP), and feed each banner through the existing `parse_node_data` with a `query` provenance label like `ip-list:<filename>`; fall back to host-root `asn`/`org`/`isp` when a banner omits them
- [x] 2.3 Treat a not-found host lookup (Shodan APIError "No information available" / 404) as a skip: count it, log at debug, continue — never call `api.scan`
- [x] 2.4 Bound the run by rate-limit pacing and an optional `--max-ips` cap: stop cleanly when the cap is reached, leaving remaining IPs unprocessed (no query-credit ceiling — host lookups are credit-free)

## 3. CLI, output, and summary

- [x] 3.1 Add `--ips <file>` (plus optional `--max-ips N` and `--rate`/sleep) to the scanner CLI and route it to `scan_from_ip_list` (mutually exclusive with the default query-based run)
- [x] 3.2 Write the gathered results as a JSON dump to `OUTPUT_DIR` in the same shape as a query-based scan (loadable by `db-import`); do not persist directly
- [x] 3.3 Print a run summary: total IPs read, unique IPs, found in Shodan, skipped (not found), lookups performed, and elapsed time (note when a `--max-ips` cap stopped the run)

## 4. Tests

- [x] 4.1 Test the host-lookup mapping with a recorded `api.host` fixture (mocked Shodan): Bitcoin service → node record, non-Bitcoin ports excluded, caller-supplied port honored, host-root field fallback
- [x] 4.2 Test skip-on-not-found (mocked APIError) and that `api.scan` is never called
- [x] 4.3 Test the `--max-ips` cap stops the run mid-list, that no query-credit ceiling is applied, and that the summary counts are correct

## 5. Docs

- [x] 5.1 Document the `--ips` flow (cost: 0 query/scan credits — host lookups are free; bounded by ~1 req/s rate limit, ~3.5 h for ~12.7k IPs; skips IPs not in Shodan; then `db-import`) in `docs/bitcoin-scanner.md` and `README.md`
- [x] 5.2 Add the `--ips` command and a note on sourcing IPs (peer-observer / `bitcoin-cli getnodeaddresses`) to `CLAUDE.md`
