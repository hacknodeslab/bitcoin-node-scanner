# background-scan Specification

## Purpose

Runs Shodan scans as background jobs so the HTTP API stays responsive: a scan is triggered via the API, executes asynchronously through a tracked job state machine (pending → running → completed/failed), enforces single-flight execution, and persists its results to the database. IP-reputation enrichment runs reuse the same job machinery, discriminated by `job_type`, with single-flight enforced per job type.

## Requirements

### Requirement: Scan executes asynchronously
The system SHALL run scans in a background thread so that the HTTP response is returned immediately upon scan trigger.

#### Scenario: Scan job returns immediately
- **WHEN** `POST /api/v1/scans` is called
- **THEN** the HTTP response SHALL be returned within 500ms regardless of scan duration

#### Scenario: Scan runs to completion in background
- **WHEN** a scan job is started
- **THEN** the scanner SHALL execute fully and update the job record to `completed` or `failed` upon finish

### Requirement: Scan job state machine
The system SHALL track scan job lifecycle through states: `pending` → `running` → `completed` | `failed`.

#### Scenario: Job transitions from pending to running
- **WHEN** the background worker picks up a pending scan job
- **THEN** the job status SHALL be updated to `running` and `started_at` SHALL be set

#### Scenario: Job transitions to completed on success
- **WHEN** the scanner finishes without exception
- **THEN** the job status SHALL be updated to `completed`, `finished_at` SHALL be set, and `result_summary` SHALL contain node counts by risk level

#### Scenario: Job transitions to failed on error
- **WHEN** the scanner raises an unhandled exception
- **THEN** the job status SHALL be updated to `failed`, `finished_at` SHALL be set, and `result_summary` SHALL contain the error message

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

### Requirement: Scan results persisted to database
The system SHALL store all discovered nodes from each scan run into the existing database tables.

#### Scenario: Nodes saved after scan completes
- **WHEN** a background scan completes successfully
- **THEN** all discovered nodes SHALL be persisted via the existing `NodeRepository` and be queryable via `GET /api/v1/nodes`

### Requirement: Enrichment executes asynchronously
Enrichment jobs SHALL run in the same background thread-pool mechanism as scans and follow the same `pending` → `running` → `completed` | `failed` state machine.

#### Scenario: Enrichment job returns immediately
- **WHEN** `POST /api/v1/enrichment/run` is called
- **THEN** the HTTP response SHALL be returned within 500ms regardless of enrichment duration

#### Scenario: Enrichment failure recorded
- **WHEN** the enrichment run raises an unhandled exception
- **THEN** the job status SHALL be `failed` with the error message in `result_summary`

### Requirement: Active-job uniqueness enforced by the database
The `scan_jobs` table SHALL have a unique partial index on `job_type` for rows whose status is `pending` or `running`. When creating a job violates it (a concurrent request won the race), the endpoint SHALL roll back and return HTTP 409 without queueing a background task.

#### Scenario: Raced admission
- **WHEN** two `POST /api/v1/enrichment/run` requests both pass the active-job check
- **THEN** exactly one job SHALL be created and the other request SHALL receive HTTP 409
