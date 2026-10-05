# web-api Specification

## Purpose

Defines the FastAPI backend at `/api/v1/*`: a key-authenticated (plus CSRF for mutations) JSON API that exposes the scanned-node list, aggregate stats, the CVE catalog, background scan jobs, and the Nostr relay CDN-recon endpoints consumed by the Next.js dashboard.

## Requirements
### Requirement: API server starts and serves requests
The system SHALL provide a FastAPI HTTP server runnable via `uvicorn src.web.main:app` that listens on a configurable host and port.

#### Scenario: Server starts with valid configuration
- **WHEN** `WEB_API_KEY` environment variable is set and the server is started
- **THEN** the server SHALL bind to the configured host/port and respond to HTTP requests

#### Scenario: Server refuses to start without API key
- **WHEN** `WEB_API_KEY` environment variable is not set
- **THEN** the server SHALL raise a configuration error and exit with a non-zero status code

### Requirement: API key authentication on all endpoints
The system SHALL require a valid `X-API-Key` header on all non-documentation endpoints.

#### Scenario: Request with valid API key is accepted
- **WHEN** a request includes `X-API-Key: <correct-key>` header
- **THEN** the server SHALL process the request and return the expected response

#### Scenario: Request with missing or invalid API key is rejected
- **WHEN** a request is made without `X-API-Key` or with an incorrect key
- **THEN** the server SHALL return HTTP 401 Unauthorized

### Requirement: Node list endpoint
The system SHALL expose `GET /api/v1/nodes` returning a paginated list of scanned nodes from the database.

#### Scenario: List nodes with default pagination
- **WHEN** `GET /api/v1/nodes` is called with a valid API key
- **THEN** the response SHALL return up to 100 nodes as JSON with fields: `ip`, `port`, `version`, `risk_level`, `country`, `last_seen`

#### Scenario: Filter nodes by risk level
- **WHEN** `GET /api/v1/nodes?risk_level=CRITICAL` is called
- **THEN** the response SHALL return only nodes with `risk_level == "CRITICAL"`

### Requirement: Statistics endpoint
The system SHALL expose `GET /api/v1/stats` returning aggregate scan statistics.

#### Scenario: Stats returns summary counts
- **WHEN** `GET /api/v1/stats` is called with a valid API key
- **THEN** the response SHALL return JSON with: `total_nodes`, `by_risk_level` (object), `by_country` (top 10), `vulnerable_versions_count`, `last_scan_at`

### Requirement: Trigger scan endpoint
The system SHALL expose `POST /api/v1/scans` to initiate a new background scan.

#### Scenario: Scan triggered successfully
- **WHEN** `POST /api/v1/scans` is called and no other scan is running
- **THEN** the server SHALL create a scan job record and return HTTP 202 Accepted with `{"job_id": "<uuid>", "status": "pending"}`

#### Scenario: Concurrent scan is rejected
- **WHEN** `POST /api/v1/scans` is called while a scan is already running
- **THEN** the server SHALL return HTTP 409 Conflict with an explanatory message

### Requirement: Scan job status endpoint
The system SHALL expose `GET /api/v1/scans/{job_id}` to retrieve scan job status.

#### Scenario: Get status of existing job
- **WHEN** `GET /api/v1/scans/{job_id}` is called with a valid job ID
- **THEN** the response SHALL return JSON with: `job_id`, `status` (pending/running/completed/failed), `started_at`, `finished_at`, `result_summary`

#### Scenario: Get status of non-existent job
- **WHEN** `GET /api/v1/scans/{job_id}` is called with an unknown job ID
- **THEN** the server SHALL return HTTP 404 Not Found

### Requirement: sort_by and sort_dir params on node list
`GET /api/v1/nodes` SHALL accept optional `sort_by` (string) and `sort_dir` (`asc`|`desc`) query parameters. Allowed `sort_by` values: `ip`, `port`, `version`, `risk_level`, `country_name`, `geo_country_name`, `last_seen`. Default: `sort_by=last_seen`, `sort_dir=desc`.

#### Scenario: Default sort preserved when params absent
- **WHEN** `sort_by` and `sort_dir` are not provided
- **THEN** results are ordered by `last_seen DESC` (existing behavior unchanged)

#### Scenario: Custom sort applied when params present
- **WHEN** `?sort_by=risk_level&sort_dir=asc` is provided
- **THEN** results are ordered by `risk_level ASC`

### Requirement: country param on node list
`GET /api/v1/nodes` SHALL accept an optional `country` query parameter. When present, results SHALL be filtered to nodes where `country_name` matches (case-insensitive).

#### Scenario: country param filters results
- **WHEN** `?country=France` is provided
- **THEN** only nodes with `country_name = 'France'` (case-insensitive) are returned

### Requirement: GET /api/v1/nodes/countries endpoint
A new endpoint `GET /api/v1/nodes/countries` SHALL return a JSON array of distinct non-null `country_name` strings, sorted alphabetically, limited to 100 entries.

#### Scenario: Returns alphabetical country list
- **WHEN** request is made with valid API key
- **THEN** response is 200 with a JSON array of strings, alphabetically sorted

#### Scenario: Requires API key
- **WHEN** no `X-API-Key` header is provided
- **THEN** response is 401

### Requirement: X-Total-Count header on node list
`GET /api/v1/nodes` SHALL set an `X-Total-Count` response header whose value is the count of nodes matching the active filters (`risk_level`, `country`, `exposed`, `tor`), ignoring `limit` and `offset`. The header SHALL be present on every successful (HTTP 200) response from this endpoint, including responses with an empty body.

#### Scenario: Header reflects total ignoring limit and offset
- **WHEN** `GET /api/v1/nodes?limit=10&offset=0` is called and 137 nodes match (no other filters)
- **THEN** the response SHALL set `X-Total-Count: 137` and the JSON body SHALL contain at most 10 nodes

#### Scenario: Header reflects filtered total
- **WHEN** `GET /api/v1/nodes?risk_level=CRITICAL&limit=10` is called and 23 nodes have `risk_level=CRITICAL`
- **THEN** the response SHALL set `X-Total-Count: 23`

#### Scenario: Header is present when no nodes match
- **WHEN** `GET /api/v1/nodes?country=ZZ` is called and zero nodes match
- **THEN** the response SHALL set `X-Total-Count: 0` and the JSON body SHALL be `[]`


### Requirement: Node detail endpoint exposes active CVEs

The system SHALL expose `GET /api/v1/nodes/{id}` returning the full node record plus the list of active CVEs linked to that node. Each CVE entry in the response SHALL include `cve_id`, `severity`, `cvss_score`, `detected_at`, and `detected_version`. By default only active links (`resolved_at IS NULL`) are returned; passing `?include_resolved=true` SHALL include resolved links with their `resolved_at` timestamp.

#### Scenario: Node detail returns linked CVEs
- **WHEN** `GET /api/v1/nodes/42` is called for a node that has 3 active CVE links
- **THEN** the response SHALL include a `cves` array of length 3 sorted by `cvss_score DESC` (NULLs last), each with `cve_id`, `severity`, `cvss_score`, `detected_at`, `detected_version`

#### Scenario: Node detail with no CVEs
- **WHEN** `GET /api/v1/nodes/{id}` is called for a node with no linked CVEs
- **THEN** the response SHALL include `cves: []`

#### Scenario: Include resolved CVEs on demand
- **WHEN** `GET /api/v1/nodes/{id}?include_resolved=true` is called for a node with 1 active and 2 resolved links
- **THEN** the response SHALL include all 3 entries, with `resolved_at` populated for the resolved ones and `null` for the active one

### Requirement: Node list includes CVE summary

`GET /api/v1/nodes` SHALL include `cve_count` (integer count of active CVE links) and `top_cve` (the active CVE with the highest `cvss_score`, or `null` if none) for each node in the paginated response. The full per-node CVE list is NOT returned by the list endpoint to keep responses bounded.

#### Scenario: List response includes CVE summary fields
- **WHEN** `GET /api/v1/nodes` returns a node with 2 active CVE links
- **THEN** that node entry SHALL include `cve_count: 2` and `top_cve: {cve_id, severity, cvss_score}` for the highest-scored active link

#### Scenario: List response for clean node
- **WHEN** `GET /api/v1/nodes` returns a node with no active CVE links
- **THEN** that node entry SHALL include `cve_count: 0` and `top_cve: null`

### Requirement: Vulnerabilities endpoint exposes affected nodes

The system SHALL expose `GET /api/v1/vulnerabilities/{cve_id}/nodes` returning the list of nodes currently linked to that CVE (i.e., active links in `node_vulnerabilities`). Response items SHALL include `ip`, `port`, `version`, `risk_level`, `country_name`, `last_seen`.

#### Scenario: List nodes affected by a CVE
- **WHEN** `GET /api/v1/vulnerabilities/CVE-2018-17144/nodes` is called and 7 nodes have an active link to that CVE
- **THEN** the response SHALL return those 7 nodes with the listed fields

#### Scenario: CVE not in catalog
- **WHEN** `GET /api/v1/vulnerabilities/CVE-9999-99999/nodes` is called for a CVE not present in `cve_entries`
- **THEN** the server SHALL return HTTP 404 Not Found


### Requirement: Node payload exposes is_example
The system SHALL include a boolean field `is_example` in the per-node objects returned by `GET /api/v1/nodes` and `GET /api/v1/nodes/{id}` (or equivalent detail endpoint). The value SHALL reflect the persisted `Node.is_example` column.

#### Scenario: List response includes the field
- **WHEN** a client calls `GET /api/v1/nodes` with a valid API key and at least one node exists
- **THEN** every node object in the response SHALL include `is_example: true` or `is_example: false`

#### Scenario: Detail response includes the field
- **WHEN** a client requests the detail of a single node
- **THEN** the response object SHALL include `is_example`

### Requirement: Filter nodes by example flag
The system SHALL accept an optional `is_example` query parameter on `GET /api/v1/nodes` that filters results by the `is_example` column. Accepted values: `true`, `false`. Omitting the parameter SHALL leave the default behavior unchanged (example nodes are included).

#### Scenario: Exclude example nodes
- **WHEN** a client calls `GET /api/v1/nodes?is_example=false`
- **THEN** the response SHALL contain only nodes whose `is_example` field is `false`

#### Scenario: Only example nodes
- **WHEN** a client calls `GET /api/v1/nodes?is_example=true`
- **THEN** the response SHALL contain only nodes whose `is_example` field is `true`

#### Scenario: Default behavior unchanged
- **WHEN** a client calls `GET /api/v1/nodes` with no `is_example` parameter
- **THEN** the response SHALL include both example and non-example nodes (subject to other filters and pagination)

#### Scenario: Filter combines with risk_level
- **WHEN** a client calls `GET /api/v1/nodes?risk_level=CRITICAL&is_example=false`
- **THEN** the response SHALL contain only non-example nodes whose `risk_level` is `CRITICAL`

#### Scenario: Invalid value is rejected
- **WHEN** a client calls `GET /api/v1/nodes?is_example=maybe`
- **THEN** the server SHALL respond with HTTP 422 Unprocessable Entity

### Requirement: Vulnerabilities catalog exposes affected node count

The `GET /api/v1/vulnerabilities` catalog response SHALL include, for each CVE entry, an `affected_node_count` field giving the number of nodes currently linked to that CVE (active links in `node_vulnerabilities`). The count SHALL be computed without issuing one query per CVE.

#### Scenario: Catalog item includes affected node count

- **WHEN** `GET /api/v1/vulnerabilities` is called and CVE-2018-17144 has 7 active node links
- **THEN** that CVE's catalog item SHALL include `affected_node_count: 7`

#### Scenario: CVE with no affected nodes

- **WHEN** a CVE in the catalog has no active node links
- **THEN** its catalog item SHALL include `affected_node_count: 0`

### Requirement: Nostr relay list endpoint

The API SHALL expose `GET /api/v1/nostr/relays` returning a paginated list of relays from the latest scan, filterable by `verdict`, `provider`, and `behind_cdn`, behind the existing API-key authentication.

#### Scenario: Paginated relay list

- **WHEN** an authenticated client requests `GET /api/v1/nostr/relays`
- **THEN** the response is a paginated list of relay items, each including `host`, `verdict`, `providers`, and `ips`

#### Scenario: Filter by provider

- **WHEN** the request includes `?provider=cloudflare`
- **THEN** only relays whose providers include `cloudflare` are returned

#### Scenario: Filter to relays behind a CDN

- **WHEN** the request includes `?behind_cdn=true`
- **THEN** relays with verdict `direct`, `dns_error`, or `skipped` are excluded

#### Scenario: Unauthenticated request rejected

- **WHEN** the request omits a valid API key
- **THEN** the API responds with `401 Unauthorized`

### Requirement: Nostr stats endpoint

The API SHALL expose `GET /api/v1/nostr/stats` returning aggregates for the latest scan: counts per verdict, `total`, `resolved`, `behind_any_cdn`, and the percentage of resolved relays behind any CDN.

#### Scenario: Aggregate stats returned

- **WHEN** an authenticated client requests `GET /api/v1/nostr/stats`
- **THEN** the response includes per-verdict counts, `total`, `resolved`, `behind_any_cdn`, and the behind-CDN percentage

#### Scenario: No scans yet

- **WHEN** no Nostr scan has been imported
- **THEN** the endpoint returns zeroed/empty aggregates rather than an error

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
