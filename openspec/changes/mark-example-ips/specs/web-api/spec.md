## ADDED Requirements

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
