## ADDED Requirements

### Requirement: Pluggable enricher protocol
The system SHALL define an `Enricher` protocol in `src/enrichers/` with a `name` attribute, an `available()` method, and a batch `enrich(ips)` method returning a per-IP result for each IP it processed. The orchestrator SHALL discover enrichers from a single registry, so that adding a source requires only a new module, a registry entry, and its `<name>_checked_at` timestamp column.

#### Scenario: New source registered without schema change
- **WHEN** a new enricher module implementing the protocol is added to the registry with its `<name>_checked_at` column
- **THEN** the orchestrator SHALL run it and store its result under its `name` in `sources_json`, with no other schema change

#### Scenario: Unavailable enricher is skipped
- **WHEN** an enricher's `available()` returns false
- **THEN** the orchestrator SHALL NOT call its `enrich` method, SHALL log `enricher unavailable: <name>` once per run, and SHALL record no error for it

### Requirement: Per-source failure isolation
The orchestrator SHALL run each available enricher independently. An exception or HTTP failure in one source SHALL be logged and recorded as `status: "error"` for that source in `sources_json`, and SHALL NOT prevent other sources from running or results from being persisted.

#### Scenario: One source fails, the other persists
- **WHEN** AbuseIPDB raises a connection error and the blocklist source succeeds for IP `X`
- **THEN** the `ip_reputation` row for `X` SHALL contain the blocklist result, `sources_json.abuseipdb.status` SHALL be `"error"`, and `reputation_enriched_at` SHALL be set

#### Scenario: Failed source stays due
- **WHEN** the blocklist source succeeds and AbuseIPDB fails for IP `X`
- **THEN** `blocklists_checked_at` SHALL be set, `abuseipdb_checked_at` SHALL remain unchanged, and `X` SHALL be a candidate for AbuseIPDB on the next run

#### Scenario: All sources fail
- **WHEN** every available source fails for IP `X`
- **THEN** `sources_json` SHALL record each error and no `<source>_checked_at` or `reputation_enriched_at` SHALL change, so the IP is retried on the next run

### Requirement: AbuseIPDB source
The system SHALL provide an `abuseipdb` enricher that queries the AbuseIPDB v2 `check` endpoint per IP and maps `abuseConfidenceScore`, `totalReports`, and `lastReportedAt` into `abuse_confidence_score`, `abuse_total_reports`, and `abuse_last_reported_at`. It SHALL be available only when `ABUSEIPDB_API_KEY` is set. It SHALL use a request timeout, retry with backoff on connection errors and 5xx responses, and send a User-Agent identifying the project.

#### Scenario: No API key
- **WHEN** `ABUSEIPDB_API_KEY` is unset
- **THEN** `available()` SHALL return false and no request to AbuseIPDB SHALL be made

#### Scenario: Successful lookup maps fields
- **WHEN** AbuseIPDB returns `abuseConfidenceScore=82`, `totalReports=41`, `lastReportedAt="2026-09-30T10:00:00+00:00"`
- **THEN** the stored row SHALL have `abuse_confidence_score=82`, `abuse_total_reports=41`, and `abuse_last_reported_at` equal to that timestamp

#### Scenario: Rejected API key stops the source without exhausting the quota
- **WHEN** AbuseIPDB responds with HTTP 401 or 403
- **THEN** the enricher SHALL stop issuing requests for the rest of the run after that single request, and SHALL NOT mark the day's quota as exhausted

#### Scenario: HTTP 429 stops the source
- **WHEN** AbuseIPDB responds with HTTP 429
- **THEN** the enricher SHALL stop issuing requests for the rest of the run, mark today's quota for `abuseipdb` as exhausted, and leave the remaining IPs not attempted (not errored)

### Requirement: Public blocklist source
The system SHALL provide a `blocklists` enricher that downloads the configured public blocklists (default ids `firehol_level1`, `spamhaus_drop`, `feodo`, `tor_exit`, overridable via `BLOCKLISTS`), caches each payload under `BLOCKLIST_CACHE_DIR` for 24 hours with validation and atomic writes, and matches IPv4 and IPv6 addresses locally by CIDR. It SHALL send no node IP to any third party. The result SHALL be the list of matching list ids, `[]` when the IP matched none.

#### Scenario: IP inside a listed CIDR
- **WHEN** the `spamhaus_drop` list contains `203.0.113.0/24` and the IP is `203.0.113.7`
- **THEN** the IP's `blocklists` SHALL include `"spamhaus_drop"`

#### Scenario: Clean IP
- **WHEN** the IP matches no configured list
- **THEN** `blocklists` SHALL be `[]` (not null)

#### Scenario: One list fails to download with no cache
- **WHEN** the `feodo` download fails and no cached copy exists
- **THEN** the other lists SHALL still be matched and `sources_json.blocklists` SHALL record `feodo` as failed

#### Scenario: Stale cache used on refresh failure
- **WHEN** a cached list is older than 24 hours and the refresh fails
- **THEN** the stale cached copy SHALL be used and the failure SHALL be logged

### Requirement: Persistent per-source daily quota
The system SHALL track per-source call counts per UTC day in the database and SHALL NOT issue an AbuseIPDB request once that day's count reaches `ABUSEIPDB_DAILY_QUOTA` (default 1000). The count SHALL be shared by CLI and API runs and survive process restarts, and increments SHALL be atomic so concurrent runs neither lose counts nor fail when both create the day's row. Consecutive AbuseIPDB requests SHALL be at least `ABUSEIPDB_MIN_INTERVAL` seconds apart (default 1).

#### Scenario: Quota reached mid-run
- **WHEN** 998 AbuseIPDB calls were already made today and a run has 10 candidate IPs
- **THEN** exactly 2 AbuseIPDB requests SHALL be made and the other 8 IPs SHALL remain pending for AbuseIPDB

#### Scenario: Quota resets next UTC day
- **WHEN** yesterday's quota was exhausted and a run starts after 00:00 UTC
- **THEN** AbuseIPDB requests SHALL be allowed again up to the full quota

#### Scenario: Concurrent runs share the budget
- **WHEN** two runs consume from the same source on the same UTC day, including the first call of the day
- **THEN** every successful call SHALL be counted exactly once and neither run SHALL fail on the day's row insert

#### Scenario: Quota persists across restarts
- **WHEN** a run makes 600 calls, the process exits, and a new run starts the same UTC day
- **THEN** the new run SHALL allow at most 400 AbuseIPDB calls

### Requirement: Reputation stored once per IP
Results SHALL be upserted into `ip_reputation` keyed by `ip`, so every node row sharing that IP reads the same reputation. For each source that succeeded for the IP, `<source>_checked_at` SHALL be set to the run time; `reputation_enriched_at` SHALL be set to the run time when at least one source succeeded (display only).

#### Scenario: Two ports, one reputation row
- **WHEN** nodes `(X, 8333)` and `(X, 8332)` exist and IP `X` is enriched
- **THEN** exactly one `ip_reputation` row SHALL exist for `X` and both nodes' detail payloads SHALL show it

#### Scenario: Re-enrichment updates in place
- **WHEN** IP `X` already has a row and is enriched again
- **THEN** the same row SHALL be updated and `first_enriched_at` SHALL be unchanged

### Requirement: Example IPs are never enriched
The system SHALL exclude IPs of nodes with `is_example = true` from candidate selection and SHALL additionally skip any IP for which `is_example_ip()` is true before calling any source.

#### Scenario: Backfill over a DB with example nodes
- **WHEN** the database contains N example nodes and enrichment runs without limit
- **THEN** no request SHALL be made for any example IP and no `ip_reputation` row SHALL be created for them

### Requirement: Backfill command
The system SHALL provide `python -m src.db.cli db-enrich-ips` with options `--limit N`, `--source <name>`, and `--dry-run`. Candidates SHALL be distinct non-example IPs for which at least one of the run's available sources has a `<source>_checked_at` that is null or older than `REPUTATION_STALE_DAYS` (default 7); each source SHALL only be called for the IPs it is due on, ordered by the highest risk level among their nodes (CRITICAL, HIGH, MEDIUM, LOW, then unrated), then never-enriched first, then oldest enrichment first. Re-running the command SHALL resume where the previous run stopped.

#### Scenario: Risk ordering
- **WHEN** candidates include LOW, CRITICAL and MEDIUM IPs and `--limit 1` is given
- **THEN** only the CRITICAL IP SHALL be enriched

#### Scenario: Recently enriched IPs skipped
- **WHEN** every available source checked an IP 2 days ago and `REPUTATION_STALE_DAYS=7`
- **THEN** it SHALL NOT be a candidate

#### Scenario: Blocklist-only run leaves IPs pending for AbuseIPDB
- **WHEN** `db-enrich-ips --source blocklists` runs and then `db-enrich-ips --source abuseipdb` runs with a key
- **THEN** the second run SHALL select the IPs AbuseIPDB has never checked

#### Scenario: Quota-bound source not re-spent
- **WHEN** an IP's `abuseipdb_checked_at` is fresh but its `blocklists_checked_at` is stale
- **THEN** the run SHALL re-check it against the blocklists and SHALL NOT call AbuseIPDB for it

#### Scenario: Source filter
- **WHEN** `--source blocklists` is given
- **THEN** only the blocklist enricher SHALL run and no AbuseIPDB request SHALL be made

#### Scenario: Dry run is offline
- **WHEN** `--dry-run --limit 2000` is given with 1,000 AbuseIPDB calls remaining today
- **THEN** the command SHALL print candidate counts per risk level, the available sources, and that AbuseIPDB would stop after 1,000 IPs, and SHALL make no HTTP request and write nothing to the database or the blocklist cache

#### Scenario: No keys configured
- **WHEN** no `ABUSEIPDB_API_KEY` is set and the command runs
- **THEN** it SHALL log `enricher unavailable: abuseipdb`, run the blocklist source, and exit with status 0
