## ADDED Requirements

### Requirement: IP reputation persistence
The system SHALL store IP reputation in an `ip_reputation` table with a unique `ip`, typed columns `abuse_confidence_score`, `abuse_total_reports`, `abuse_last_reported_at`, `blocklists` (JSON list), one `<source>_checked_at` timestamp per source (`abuseipdb_checked_at`, `blocklists_checked_at`), `reputation_enriched_at` (indexed), `first_enriched_at`, `updated_at`, and a `sources_json` column holding per-source status, timestamp, error and raw payload. The table SHALL have no foreign key to `nodes` and SHALL NOT add or change any column on `nodes`.

#### Scenario: Migration is additive
- **WHEN** migration `009` is applied to a database with existing nodes
- **THEN** the `nodes` table columns and rows SHALL be unchanged and `ip_reputation` SHALL exist empty

#### Scenario: Unique IP enforced
- **WHEN** a second insert for an IP that already has a row is attempted
- **THEN** the repository SHALL update the existing row instead

### Requirement: Enrichment quota persistence
The system SHALL store per-source daily call counts in an `enrichment_quota` table with columns `source`, `day_utc`, `calls`, and `exhausted` (set when the provider reports the day's budget gone, e.g. HTTP 429), unique on `(source, day_utc)`.

#### Scenario: Counter increments per call
- **WHEN** three AbuseIPDB calls are made on the same UTC day
- **THEN** the `(abuseipdb, <day>)` row SHALL have `calls = 3`

### Requirement: Job type on background jobs
The `scan_jobs` table SHALL have a non-null `job_type` column with default `'scan'`; migration `009` SHALL set existing rows to `'scan'`.

#### Scenario: Existing jobs default to scan
- **WHEN** migration `009` runs on a database with existing scan jobs
- **THEN** every existing job SHALL have `job_type = 'scan'`
