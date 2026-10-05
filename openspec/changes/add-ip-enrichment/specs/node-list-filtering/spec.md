## ADDED Requirements

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
