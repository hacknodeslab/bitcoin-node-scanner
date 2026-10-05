## MODIFIED Requirements

### Requirement: Only one scan runs at a time
The system SHALL enforce a single-concurrent-job constraint per job type. Jobs SHALL carry a `job_type` of `scan` or `enrichment`; existing jobs SHALL be treated as `scan`. A job of one type SHALL NOT block a job of the other type.

#### Scenario: Second scan request rejected while scan is active
- **WHEN** a job with `job_type = "scan"` exists with status `pending` or `running`
- **THEN** `POST /api/v1/scans` SHALL return HTTP 409 and no new job SHALL be created

#### Scenario: Enrichment does not block a scan
- **WHEN** a job with `job_type = "enrichment"` is `running` and no scan job is active
- **THEN** `POST /api/v1/scans` SHALL create a new scan job

#### Scenario: Second enrichment rejected while enrichment is active
- **WHEN** a job with `job_type = "enrichment"` exists with status `pending` or `running`
- **THEN** `POST /api/v1/enrichment/run` SHALL return HTTP 409 and no new job SHALL be created

## ADDED Requirements

### Requirement: Enrichment executes asynchronously
Enrichment jobs SHALL run in the same background thread-pool mechanism as scans and follow the same `pending` → `running` → `completed` | `failed` state machine.

#### Scenario: Enrichment job returns immediately
- **WHEN** `POST /api/v1/enrichment/run` is called
- **THEN** the HTTP response SHALL be returned within 500ms regardless of enrichment duration

#### Scenario: Enrichment failure recorded
- **WHEN** the enrichment run raises an unhandled exception
- **THEN** the job status SHALL be `failed` with the error message in `result_summary`
