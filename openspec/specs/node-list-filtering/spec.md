# node-list-filtering Specification

## Purpose

Defines server-side filtering of the node list endpoint: filtering by country (with a distinct-countries lookup), by the example-data flag, and by IP reputation (public-blocklist membership, AbuseIPDB score and reports).

## Requirements

### Requirement: Filter nodes by country
The API SHALL accept a `country` query parameter on `GET /api/v1/nodes` that filters results to nodes whose `country_name` matches the given value (case-insensitive).

#### Scenario: Filter returns matching nodes
- **WHEN** a request is made with `?country=Germany`
- **THEN** only nodes with `country_name` equal to "Germany" (case-insensitive) are returned

#### Scenario: Filter with no matches returns empty list
- **WHEN** a request is made with `?country=Narnia`
- **THEN** an empty list is returned with status 200

#### Scenario: Filter combines with risk_level
- **WHEN** a request includes both `?risk_level=CRITICAL&country=Germany`
- **THEN** only nodes matching both conditions are returned

### Requirement: List distinct countries endpoint
The API SHALL provide `GET /api/v1/nodes/countries` returning a sorted list of distinct non-null `country_name` values present in the database.

#### Scenario: Returns known countries
- **WHEN** nodes from Germany, US, and France exist in the DB
- **THEN** the endpoint returns `["France", "Germany", "United States"]` (alphabetically sorted)

#### Scenario: Returns empty list when no nodes
- **WHEN** the nodes table is empty
- **THEN** the endpoint returns `[]`

#### Scenario: Requires API key
- **WHEN** the request has no `X-API-Key` header
- **THEN** the endpoint returns 401


### Requirement: Filter nodes by example flag
The API SHALL accept an `is_example` query parameter on `GET /api/v1/nodes` that filters results by the `is_example` column. The parameter accepts `true` or `false`; omitting it leaves the default behavior (example nodes included).

#### Scenario: Filter excludes example nodes
- **WHEN** a request is made with `?is_example=false`
- **THEN** the response contains only nodes whose `is_example` is `false`

#### Scenario: Filter returns only example nodes
- **WHEN** a request is made with `?is_example=true`
- **THEN** the response contains only nodes whose `is_example` is `true`

#### Scenario: Filter combines with country
- **WHEN** a request is made with `?country=Germany&is_example=false`
- **THEN** the response contains only nodes whose `country_name` equals `Germany` (case-insensitive) and whose `is_example` is `false`

### Requirement: Filter nodes by blocklist membership
The API SHALL accept on `GET /api/v1/nodes` a `blocklisted` query parameter (only `true` supported) returning nodes whose IP has a non-empty `blocklists` list in `ip_reputation`, and a `blocklist` parameter returning nodes whose IP is on that blocklist id. `blocklist` SHALL be validated against the known blocklist ids (`firehol_level1`, `spamhaus_drop`, `feodo`, `tor_exit`). Both filters SHALL combine with the other filters and SHALL apply to the `X-Total-Count` header. Nodes whose IP was never enriched SHALL NOT match.

#### Scenario: Any blocklist
- **WHEN** `GET /api/v1/nodes?blocklisted=true` is called and IP `A` (two ports) is on `spamhaus_drop`, IP `B` is on `tor_exit`, IP `C` is clean
- **THEN** the response SHALL contain the three nodes of `A` and `B` and `X-Total-Count` SHALL be `3`

#### Scenario: Specific blocklist
- **WHEN** `GET /api/v1/nodes?blocklist=tor_exit` is called
- **THEN** only nodes whose IP's `blocklists` contains `tor_exit` SHALL be returned

#### Scenario: Unknown blocklist id
- **WHEN** `GET /api/v1/nodes?blocklist=greynoise` is called
- **THEN** the API SHALL return HTTP 422

#### Scenario: Negated filter unsupported
- **WHEN** `GET /api/v1/nodes?blocklisted=false` is called
- **THEN** the API SHALL return HTTP 400

### Requirement: Filter nodes by AbuseIPDB reputation
The API SHALL accept on `GET /api/v1/nodes` an `abuse_min` integer parameter (0–100) returning nodes whose IP has `abuse_confidence_score >= abuse_min` in `ip_reputation`, and a `reported` parameter (only `true` supported) returning nodes whose IP has `abuse_total_reports > 0`. IPs never checked by AbuseIPDB SHALL NOT match either filter. Both SHALL combine with other filters and apply to `X-Total-Count`.

#### Scenario: Minimum score
- **WHEN** `GET /api/v1/nodes?abuse_min=75` is called and IP `A` scores 90, IP `B` scores 30
- **THEN** only the nodes of `A` SHALL be returned

#### Scenario: Out-of-range score
- **WHEN** `GET /api/v1/nodes?abuse_min=101` is called
- **THEN** the API SHALL return HTTP 422

#### Scenario: Reported
- **WHEN** `GET /api/v1/nodes?reported=true` is called
- **THEN** only nodes whose IP has at least one AbuseIPDB report SHALL be returned; `reported=false` SHALL return HTTP 400
