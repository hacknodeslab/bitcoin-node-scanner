## ADDED Requirements

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
