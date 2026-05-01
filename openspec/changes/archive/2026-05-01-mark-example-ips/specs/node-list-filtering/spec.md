## ADDED Requirements

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
