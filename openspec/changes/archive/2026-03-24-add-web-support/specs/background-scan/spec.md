## ADDED Requirements

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
The system SHALL enforce a single-concurrent-scan constraint.

#### Scenario: Second scan request rejected while scan is active
- **WHEN** a scan job exists with status `pending` or `running`
- **THEN** `POST /api/v1/scans` SHALL return HTTP 409 and no new job SHALL be created

### Requirement: Scan results persisted to database
The system SHALL store all discovered nodes from each scan run into the existing database tables.

#### Scenario: Nodes saved after scan completes
- **WHEN** a background scan completes successfully
- **THEN** all discovered nodes SHALL be persisted via the existing `NodeRepository` and be queryable via `GET /api/v1/nodes`
