## ADDED Requirements

### Requirement: Node detail exposes IP reputation
`GET /api/v1/nodes/{node_id}` SHALL include a `reputation` field. When an `ip_reputation` row exists for the node's IP, it SHALL be an object with `abuse_confidence_score`, `abuse_total_reports`, `abuse_last_reported_at`, `blocklists`, `reputation_enriched_at`, `stale` (true when `reputation_enriched_at` is older than `REPUTATION_STALE_DAYS`), and `sources` (map of source name → `ok` | `error` | `skipped`). Raw source payloads SHALL NOT be exposed. When no row exists, `reputation` SHALL be `null`. `GET /api/v1/nodes` SHALL NOT change.

#### Scenario: Enriched node
- **WHEN** the node's IP has a reputation row with `abuse_confidence_score=82` and `blocklists=["feodo"]`
- **THEN** the response SHALL contain `reputation.abuse_confidence_score = 82` and `reputation.blocklists = ["feodo"]`

#### Scenario: Never-enriched node
- **WHEN** the node's IP has no reputation row
- **THEN** the response SHALL contain `"reputation": null` and all previously existing fields unchanged

### Requirement: Trigger enrichment endpoint
`POST /api/v1/enrichment/run` SHALL require the API key and CSRF token, accept an optional JSON body `{limit?: int, source?: string}` with `limit` between 1 and 1000 (default 100), create a background job with `job_type = "enrichment"`, and return HTTP 202 with the job id and status. Job status SHALL be readable via `GET /api/v1/scans/{job_id}`, whose payload SHALL include `job_type`. On completion, `result_summary` SHALL contain the number of IPs processed, per-source success/error counts, and AbuseIPDB quota remaining.

#### Scenario: Missing CSRF token
- **WHEN** the endpoint is called with a valid API key but no CSRF token
- **THEN** it SHALL return HTTP 403 and no job SHALL be created

#### Scenario: Enrichment already running
- **WHEN** an enrichment job is `pending` or `running`
- **THEN** the endpoint SHALL return HTTP 409 and no new job SHALL be created

#### Scenario: Limit out of range
- **WHEN** the body contains `limit = 5000`
- **THEN** the endpoint SHALL return HTTP 422

#### Scenario: Unknown source
- **WHEN** the body contains `source = "greynoise"`
- **THEN** the endpoint SHALL return HTTP 422
