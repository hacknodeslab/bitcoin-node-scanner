## ADDED Requirements

### Requirement: Direct node lookup by IP

The web API SHALL expose a direct lookup endpoint for nodes by IP so the dashboard's `node: open <ip>` palette command does not have to scan the paginated list.

#### Scenario: Known IP

- **WHEN** a client requests `GET /api/v1/nodes/by-ip/{ip}` with a valid `X-API-Key`
- **AND** the database contains a node matching that IP
- **THEN** the server returns 200 with the same shape as the existing `NodeOut`

#### Scenario: Unknown IP

- **WHEN** a client requests `GET /api/v1/nodes/by-ip/{ip}` with a valid `X-API-Key`
- **AND** no node matches that IP
- **THEN** the server returns 404

### Requirement: Palette argument-input mode

The command palette SHALL support commands that require a single textual argument so deferred entries (`scan: status <job_id>`, `node: filter country <code>`, `node: open <ip>`) can be invoked without leaving the keyboard surface.

#### Scenario: Argument prompt after command selection

- **WHEN** a user selects a command declared with `requiresArg`
- **THEN** the palette transitions to an argument-input row showing the command name and an input
- **AND** Enter executes the command with the entered argument
- **AND** Esc returns the palette to the command-list view

## MODIFIED Requirements

### Requirement: Palette ↔ REST parity registry

Every non-NAV palette command MUST resolve to a registered REST endpoint. The registry SHALL include the previously deferred entries once their endpoints exist.

#### Scenario: Re-enabled deferred commands map to real endpoints

- **WHEN** the parity test walks `COMMAND_SPECS`
- **THEN** `scan: status <job_id>` maps to `GET /api/v1/scans/{job_id}`
- **AND** `node: filter country <code>` maps to `GET /api/v1/nodes`
- **AND** `node: open <ip>` maps to `GET /api/v1/nodes/by-ip/{ip}`
