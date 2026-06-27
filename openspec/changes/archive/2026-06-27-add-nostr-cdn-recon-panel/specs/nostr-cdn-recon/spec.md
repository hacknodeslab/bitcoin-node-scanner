## ADDED Requirements

### Requirement: Relay host normalization

The system SHALL normalize each input line to a bare lowercase hostname before classification, accepting `wss://relay.x/`, `relay.x`, and mixed forms, and SHALL deduplicate hosts within a single run.

#### Scenario: Normalize scheme-prefixed URL

- **WHEN** the input line is `wss://relay.example.com/`
- **THEN** the system classifies the host `relay.example.com`

#### Scenario: Skip blank and comment lines

- **WHEN** an input line is empty or starts with `#`
- **THEN** the system ignores that line and does not emit a result for it

#### Scenario: Deduplicate repeated hosts

- **WHEN** the same host appears on multiple input lines (in any URL form)
- **THEN** the system classifies it exactly once

### Requirement: CDN classification by CIDR membership

The system SHALL resolve each host's A/AAAA records and classify it against the published CIDR ranges of Cloudflare, CloudFront, and Fastly, assigning a verdict of the matching provider name, a `+`-joined combination when an IP set spans multiple providers, or `direct` when no range matches.

#### Scenario: Host behind Cloudflare

- **WHEN** a host resolves to an IP inside a Cloudflare CIDR range
- **THEN** the verdict is `cloudflare` and `providers` contains `cloudflare`

#### Scenario: Host not behind any tracked CDN

- **WHEN** a host resolves to IPs that match none of the tracked ranges
- **THEN** the verdict is `direct` and `providers` is empty

#### Scenario: Host spanning multiple CDNs

- **WHEN** a host's resolved IPs match more than one provider's ranges
- **THEN** the verdict is the `+`-joined sorted provider names (e.g. `cloudflare+fastly`)

### Requirement: Non-resolvable and non-DNS hosts

The system SHALL assign the verdict `skipped` to `.onion`/`.i2p` hosts without attempting DNS resolution, and `dns_error` to hosts that fail to resolve, recording the error reason.

#### Scenario: Tor/I2P host skipped

- **WHEN** a host ends in `.onion` or `.i2p`
- **THEN** the verdict is `skipped` with reason `onion/i2p` and no DNS lookup is performed

#### Scenario: Unresolvable host

- **WHEN** a host fails A/AAAA resolution (timeout or NXDOMAIN)
- **THEN** the verdict is `dns_error`, `ips` is empty, and the error reason is recorded

### Requirement: CDN range fetch with caching and fallback

The system SHALL fetch each provider's published IP ranges and cache them for 7 days, and SHALL fall back to a hardcoded Cloudflare range list when the live Cloudflare fetch fails.

#### Scenario: Cached ranges reused within TTL

- **WHEN** a provider's range list was fetched less than 7 days ago
- **THEN** the system reads the cached copy instead of re-fetching

#### Scenario: Cloudflare fetch failure

- **WHEN** the live Cloudflare range fetch fails and no fresh cache exists
- **THEN** the system uses the hardcoded Cloudflare fallback ranges and still produces verdicts

### Requirement: Scan run produces a JSON dump

The system SHALL provide a runnable scanner (`python -m src.nostr.scanner <relays.txt>`) that writes a JSON dump to `output/` with the shape `{counts, total, resolved, behind_any_cdn, results[]}`, where each result carries `host`, `verdict`, `ips`, `providers`, and `error`.

#### Scenario: Scan writes a dump

- **WHEN** the operator runs the Nostr scanner over a relay list
- **THEN** a JSON file is written to `output/` containing per-host results and aggregate counts

#### Scenario: Aggregate counts are consistent

- **WHEN** the scan completes
- **THEN** `resolved` equals `total` minus `skipped` minus `dns_error`, and `behind_any_cdn` equals the count of results whose verdict is none of `direct`, `dns_error`, `skipped`

### Requirement: Manual import of a scan dump into the database

The system SHALL provide a CLI command `db-import-nostr <dump.json>` that persists a scan dump into the `nostr_scans` and `nostr_relays` tables without requiring the scanner to write to the database directly.

#### Scenario: Import a dump

- **WHEN** the operator runs `db-import-nostr` on a scan dump
- **THEN** a `NostrScan` session row is created and one `NostrRelay` row is upserted per result, with the relay's `last_seen` updated to the scan time

#### Scenario: Re-import updates existing relays

- **WHEN** a later dump is imported for a host already present
- **THEN** the existing relay row is updated (verdict/providers/ips/last_seen) rather than duplicated
