## ADDED Requirements

### Requirement: Blocklist filter commands
The palette SHALL offer, in the `NODES` group, `node: filter blocklisted (any list)`, which sets the query to `blocklisted=true`, and one `node: filter blocklist <id>` command per known blocklist id, which sets the query to `blocklist=<id>`. All of them SHALL map to `GET /api/v1/nodes` for REST parity.

#### Scenario: Any-list command
- **WHEN** the user runs `node: filter blocklisted (any list)`
- **THEN** the explorer query SHALL become `blocklisted=true`

#### Scenario: Per-list command
- **WHEN** the user runs `node: filter blocklist spamhaus_drop`
- **THEN** the explorer query SHALL become `blocklist=spamhaus_drop`
