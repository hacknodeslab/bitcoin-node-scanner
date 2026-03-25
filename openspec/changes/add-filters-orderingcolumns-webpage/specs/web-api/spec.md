## ADDED Requirements

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
