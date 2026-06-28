## ADDED Requirements

### Requirement: Scan from a caller-provided IP list

The scanner SHALL accept a `--ips <file>` mode that reads a list of node IPs from a file and looks each one up in Shodan, instead of discovering nodes via Shodan search queries.

#### Scenario: Invoke IP-list mode

- **WHEN** the operator runs `python -m src.scanner --ips peers.csv`
- **THEN** the scanner reads the IPs from `peers.csv`, performs a Shodan host lookup for each unique IP, and produces a scan run from the results

#### Scenario: IP-list mode does not run search queries

- **WHEN** the scanner runs in `--ips` mode
- **THEN** it SHALL NOT issue any Shodan search (`api.search`) calls and SHALL only perform per-IP host lookups

### Requirement: Tolerant input parsing

The scanner SHALL parse each input line into an IP and an optional port, accepting peer-observer's `host:port` format — IPv4 as `ip:port` and IPv6 bracketed as `[ipv6]:port` — as well as a CSV `ip,port` and a bare IP (v4 or v6) with no port. It SHALL ignore blank lines and lines beginning with `#`, validate IPs, and deduplicate by IP.

#### Scenario: IPv4 host:port (peer-observer)

- **WHEN** a line contains `1.10.205.86:8333`
- **THEN** the scanner treats `1.10.205.86` as the IP and `8333` as an expected Bitcoin port for that IP

#### Scenario: Bracketed IPv6 host:port (peer-observer)

- **WHEN** a line contains `[2001:db8::1]:8333`
- **THEN** the scanner treats `2001:db8::1` as the IP and `8333` as an expected Bitcoin port for that IP

#### Scenario: Non-default port preserved

- **WHEN** a line contains `1.120.5.214:9333`
- **THEN** the scanner records `9333` as the expected port for that IP even though it is not in the default Bitcoin port set

#### Scenario: CSV with IP and port

- **WHEN** a line contains `203.0.113.5,8333`
- **THEN** the scanner treats `203.0.113.5` as the IP and `8333` as an expected port for that IP

#### Scenario: Bare IP with no port

- **WHEN** a line contains only `203.0.113.5` (or a bare IPv6 such as `2001:db8::1`)
- **THEN** the scanner treats it as an IP with no caller-supplied port and does not mistake an unbracketed IPv6's colons for a port separator

#### Scenario: Comments and blanks ignored

- **WHEN** a line is blank or begins with `#`
- **THEN** the scanner skips it without error

#### Scenario: Duplicate IPs collapsed

- **WHEN** the same IP appears on multiple lines
- **THEN** the scanner looks it up only once, merging any additional ports as extra expected ports

#### Scenario: Invalid IP rejected

- **WHEN** a line's IP field is not a valid IP address
- **THEN** the scanner skips that line and continues processing the rest

### Requirement: Bitcoin service mapping from host lookup

For each IP found in Shodan, the scanner SHALL map every Bitcoin-relevant service banner from the host lookup into the canonical node record using the same parsing path as query-based scans, so the resulting records are equivalent. A service is Bitcoin-relevant if its port is a known Bitcoin port (mainnet/testnet/signet P2P and RPC) or matches a port supplied for that IP in the input.

#### Scenario: Bitcoin service produces a node record

- **WHEN** a looked-up IP exposes a service on a Bitcoin port (e.g. 8333)
- **THEN** the scanner produces a node record for that IP and port with the same fields as a query-discovered node (risk level, geo enrichment, version, banner, vulns)

#### Scenario: Non-Bitcoin services excluded

- **WHEN** a looked-up IP also exposes services on unrelated ports (e.g. 80, 22)
- **THEN** those services SHALL NOT produce node records

#### Scenario: Caller-supplied port honored

- **WHEN** the input supplies a port for an IP and Shodan has a banner on that port
- **THEN** the scanner includes that service even if the port is not in the default Bitcoin port set

### Requirement: Skip IPs not present in Shodan

The scanner SHALL skip any IP that Shodan has no information for (host lookup returns not-found), without aborting the run, and SHALL count how many IPs were skipped. The scanner SHALL NOT trigger on-demand active scanning.

#### Scenario: IP absent from Shodan

- **WHEN** a host lookup reports no information for an IP
- **THEN** the scanner records it as skipped (not found) and continues with the next IP

#### Scenario: No on-demand scanning

- **WHEN** an IP is not found in Shodan
- **THEN** the scanner SHALL NOT call the Shodan on-demand scan API for it

### Requirement: Rate-limit pacing and optional run cap

Shodan host lookups consume no query or scan credits, so the run is bounded by the API rate limit and an optional cap rather than a credit ceiling. The scanner SHALL pace host lookups to respect the Shodan API rate limit, and SHALL accept an optional maximum number of IPs to process per run, stopping cleanly when that cap is reached and leaving the remaining IPs unprocessed.

#### Scenario: Lookups are rate-limited

- **WHEN** the scanner performs consecutive host lookups
- **THEN** it paces the requests so as not to exceed the Shodan API rate limit

#### Scenario: Run cap reached

- **WHEN** an optional max-IPs cap is configured and reached during an IP-list run
- **THEN** the scanner stops performing further host lookups, finishes the run with the results gathered so far, and reports that the cap was reached

#### Scenario: No credit ceiling applied

- **WHEN** an IP-list run processes many IPs
- **THEN** it does not consume query or scan credits and is not stopped by the `MAX_QUERY_CREDITS_PER_SCAN` query-credit ceiling

### Requirement: JSON output and run summary

The scanner SHALL write the gathered results as a JSON dump to the output directory in the same shape as a query-based scan (so it can be loaded with `db-import`), and SHALL print a summary of the run. It SHALL NOT persist directly to the database.

#### Scenario: Dump written for import

- **WHEN** an IP-list run completes
- **THEN** a JSON dump is written to the output directory and can be loaded with `python -m src.db.cli db-import <dump>`

#### Scenario: Summary reported

- **WHEN** an IP-list run completes
- **THEN** the scanner prints the total IPs read, unique IPs, IPs found in Shodan, IPs skipped (not found), lookups performed, and elapsed time (noting if a run cap stopped it)
