## ADDED Requirements

### Requirement: Cache CVE entries in the database
The system SHALL persist fetched CVE entries in a `cve_entries` SQLite table with columns `cve_id` (primary key), `published` (datetime), `last_modified` (datetime), `severity` (text), `cvss_score` (float, nullable), `description` (text), `affected_versions` (JSON text), `fetched_at` (datetime).

#### Scenario: First-time fetch populates cache
- **WHEN** no records exist in `cve_entries` and a fetch is triggered
- **THEN** all returned CVE entries SHALL be inserted into `cve_entries` with `fetched_at` set to the current UTC time

#### Scenario: Refresh updates existing records
- **WHEN** a refresh is triggered and a CVE with the same `cve_id` already exists
- **THEN** the existing record SHALL be updated (upsert) with the latest field values and a new `fetched_at`

### Requirement: TTL-based cache invalidation
The system SHALL consider the cache stale when the most recent `fetched_at` is older than the configured TTL (default 24 hours, overridable via `NVD_CACHE_TTL_HOURS` environment variable). A stale cache SHALL trigger a background re-fetch on the next request.

#### Scenario: Cache is fresh
- **WHEN** the most recent `fetched_at` is within the TTL window
- **THEN** the service SHALL return cached records without calling the NVD API

#### Scenario: Cache is stale
- **WHEN** the most recent `fetched_at` exceeds the TTL
- **THEN** the service SHALL fetch fresh data from NVD, update the cache, and return the updated records

#### Scenario: Cache is empty
- **WHEN** `cve_entries` is empty and a request arrives
- **THEN** the service SHALL fetch from NVD synchronously and populate the cache before returning

### Requirement: Return sorted vulnerability list
The service SHALL return CVE entries sorted by `cvss_score` descending (highest severity first), with NULL scores last.

#### Scenario: Sort order on retrieval
- **WHEN** the service returns cached entries
- **THEN** entries SHALL be ordered by `cvss_score` DESC, NULLs last
