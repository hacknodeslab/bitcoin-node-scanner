## ADDED Requirements

### Requirement: Hardcoded seed server list
The system SHALL maintain a hardcoded list of at least 10 known public Electrum servers as the initial seed set for M0. Each entry SHALL include host, port, and SSL flag.

#### Scenario: Seed list loaded at startup
- **WHEN** the daemon starts
- **THEN** it attempts to connect to every server in the hardcoded seed list

#### Scenario: Duplicate servers deduplicated
- **WHEN** the seed list contains duplicate host:port entries
- **THEN** only one connection is established per unique host:port pair

### Requirement: Server registry in memory
The system SHALL maintain an in-memory registry of all known servers keyed by `host:port`, tracking connection state (connecting, connected, errored, disconnected).

#### Scenario: State transitions on connect
- **WHEN** a TCP/SSL connection to a server succeeds
- **THEN** the registry entry transitions to `connected`

#### Scenario: State transitions on disconnect
- **WHEN** a connection drops or times out
- **THEN** the registry entry transitions to `disconnected` and reconnect backoff begins
