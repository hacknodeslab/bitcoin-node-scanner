## ADDED Requirements

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
