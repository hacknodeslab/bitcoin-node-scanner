## ADDED Requirements

### Requirement: Nostr relay persistence

The system SHALL persist Nostr relays in a dedicated `nostr_relays` table keyed by host, storing `verdict`, `providers`, resolved `ips`, and `first_seen`/`last_seen` timestamps, with indexes on `host`, `verdict`, and `last_seen`. This table SHALL be independent of the `Node` table.

#### Scenario: Relay row stored

- **WHEN** a scan dump is imported
- **THEN** each result is stored as a `nostr_relays` row with its host, verdict, providers, ips, and timestamps

#### Scenario: Host uniqueness

- **WHEN** a host already exists in `nostr_relays`
- **THEN** importing a new result for that host updates the existing row (verdict/providers/ips/last_seen) rather than inserting a duplicate

### Requirement: Nostr scan session tracking

The system SHALL record each Nostr scan as a row in a dedicated `nostr_scans` table capturing the source list reference, `total`, `resolved`, `behind_any_cdn`, a timestamp, and a status, independent of the `Scan` table.

#### Scenario: Scan session created on import

- **WHEN** a scan dump is imported
- **THEN** a `nostr_scans` row is created with the scan's totals and timestamp

#### Scenario: Latest scan resolvable

- **WHEN** the stats/list endpoints query Nostr data
- **THEN** they can identify the most recent `nostr_scans` session to scope results to the latest scan
