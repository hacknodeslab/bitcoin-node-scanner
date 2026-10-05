## ADDED Requirements

### Requirement: Trends endpoint

The web API SHALL expose `GET /api/v1/trends` (API key required) with query params `days` (int, 1–3650, default 30) and `granularity` (`day` | `week` | `month`), returning the same vulnerability-trend bucketing and summary the CLI `db-trends` computes.

#### Scenario: Default window

- **WHEN** a client requests `GET /api/v1/trends` with a valid `X-API-Key`
- **THEN** the server returns 200 with `period`, `days`, `granularity`, `data` (bucket → counts) and `summary`

#### Scenario: Invalid granularity

- **WHEN** a client requests `GET /api/v1/trends?granularity=hour`
- **THEN** the server returns 422

### Requirement: Credits endpoint reads local tracking only

The web API SHALL expose `GET /api/v1/credits` (API key required) returning the Shodan credit usage recorded locally by `src/credit_tracker.py` (today, month, plan limit, remaining, end-of-month projection). The endpoint SHALL NOT call the Shodan API.

#### Scenario: Polling is free

- **WHEN** a client requests `GET /api/v1/credits` repeatedly
- **THEN** every response is computed from the local usage log and no Shodan API request is made

### Requirement: Export endpoint

The web API SHALL expose `GET /api/v1/export` (API key required) returning the same JSON dump shape as CLI `db-export`, as a downloadable attachment.

#### Scenario: Export round-trip

- **WHEN** a client downloads `GET /api/v1/export` and posts the body to `POST /api/v1/import`
- **THEN** the dump imports without data loss of the exported fields

### Requirement: Import endpoint

The web API SHALL expose `POST /api/v1/import` (API key + CSRF required) accepting a scanner/export JSON dump in the request body and importing it through the same code path as CLI `db-import`, returning per-row outcome counts.

#### Scenario: Missing CSRF token

- **WHEN** the endpoint is called with a valid API key but no CSRF token
- **THEN** it SHALL return HTTP 403 and no rows SHALL be written

#### Scenario: Malformed body

- **WHEN** the body is not a dump object, list, or single-node object
- **THEN** the server returns 400 and no rows SHALL be written

### Requirement: Geo enrichment endpoint

The web API SHALL expose `POST /api/v1/enrich-geo` (API key + CSRF required) that runs retroactive MaxMind geo enrichment as a background job reusing the `ScanJob` machinery, sharing the `enrichment` job-type single-flight with `POST /api/v1/enrichment/run`.

#### Scenario: Enrichment already running

- **WHEN** any job with `job_type = "enrichment"` is pending or running
- **THEN** the endpoint SHALL return HTTP 409 and no new job SHALL be created

#### Scenario: Geo job summary is identifiable

- **WHEN** a geo enrichment job completes
- **THEN** its `result_summary` SHALL include `kind: "geo"` and updated/skipped counts

### Requirement: Stats endpoint exposes the CLI field set

`GET /api/v1/stats` SHALL include a `period_stats` object mirroring the CLI `stats` fields (period-scoped counts, rates, top ASNs) alongside the existing all-time fields, which SHALL remain unchanged.

#### Scenario: Additive change

- **WHEN** a client requests `GET /api/v1/stats`
- **THEN** all previously existing fields are present and unchanged in meaning, and `period_stats` is present
