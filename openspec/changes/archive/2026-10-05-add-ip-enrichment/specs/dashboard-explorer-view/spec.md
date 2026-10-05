## ADDED Requirements

### Requirement: Blocklist keys in the query bar
The query bar grammar SHALL accept `blocklisted=true`, mapped to the `blocklisted` node-list parameter, and `blocklist=<id>` (case-insensitive, one of `firehol_level1`, `spamhaus_drop`, `feodo`, `tor_exit`), mapped to the `blocklist` parameter. `blocklisted=false` and unknown ids SHALL produce a warning and no filter. Both keys' values SHALL render in `alert` colour.

#### Scenario: Blocklisted filter applied
- **WHEN** the user applies `blocklisted=true`
- **THEN** the explorer SHALL fetch `GET /api/v1/nodes?blocklisted=true`

#### Scenario: Unknown list id warns
- **WHEN** the user applies `blocklist=greynoise`
- **THEN** no blocklist filter SHALL be sent and a warning listing the valid ids SHALL be produced
