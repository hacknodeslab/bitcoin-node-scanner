## MODIFIED Requirements

### Requirement: Read endpoints are publicly accessible
`GET /api/v1/nodes`, `GET /api/v1/stats`, and `GET /api/v1/nodes/countries` SHALL NOT require the `X-API-Key` header. Any client MAY call these endpoints without authentication.

#### Scenario: Nodes endpoint accessible without API key
- **WHEN** `GET /api/v1/nodes` is called without `X-API-Key`
- **THEN** the response is 200 with node data

#### Scenario: Stats endpoint accessible without API key
- **WHEN** `GET /api/v1/stats` is called without `X-API-Key`
- **THEN** the response is 200 with statistics

#### Scenario: Countries endpoint accessible without API key
- **WHEN** `GET /api/v1/nodes/countries` is called without `X-API-Key`
- **THEN** the response is 200 with the country list

### Requirement: Scan endpoints remain protected
`POST /api/v1/scans` and `GET /api/v1/scans/{job_id}` SHALL still require a valid `X-API-Key` header.

#### Scenario: Scan trigger requires API key
- **WHEN** `POST /api/v1/scans` is called without `X-API-Key`
- **THEN** the response is 401

#### Scenario: Scan status requires API key
- **WHEN** `GET /api/v1/scans/{job_id}` is called without `X-API-Key`
- **THEN** the response is 401
