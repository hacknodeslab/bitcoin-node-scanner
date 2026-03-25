## ADDED Requirements

### Requirement: Sort nodes by column
The API SHALL accept `sort_by` and `sort_dir` query parameters on `GET /api/v1/nodes`. `sort_by` MUST be one of: `ip`, `port`, `version`, `risk_level`, `country_name`, `geo_country_name`, `last_seen`. `sort_dir` MUST be `asc` or `desc` (default: `desc`). Unknown values for `sort_by` SHALL fall back to `last_seen`.

#### Scenario: Sort by last_seen descending (default)
- **WHEN** no sort params are provided
- **THEN** results are ordered by `last_seen` descending

#### Scenario: Sort by country ascending
- **WHEN** request includes `?sort_by=country_name&sort_dir=asc`
- **THEN** results are ordered alphabetically by `country_name`

#### Scenario: Invalid sort_by falls back to last_seen
- **WHEN** request includes `?sort_by=nonexistent_column`
- **THEN** results are ordered by `last_seen` descending with status 200 (no error)

#### Scenario: Sort combines with filters
- **WHEN** request includes `?risk_level=HIGH&sort_by=ip&sort_dir=asc`
- **THEN** only HIGH risk nodes are returned, sorted by IP ascending
