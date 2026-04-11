## ADDED Requirements

### Requirement: Block notification subscription
The system SHALL subscribe to `blockchain.headers.subscribe` on every connected server and record the notification with a millisecond-precision monotonic timestamp anchored to wall clock at startup.

#### Scenario: Block notification recorded
- **WHEN** a server sends a `blockchain.headers.subscribe` notification
- **THEN** the system records `(server_id, height, block_hash, timestamp_ms)` to the database within 50ms of receipt

#### Scenario: Competing tips during fork race
- **WHEN** two servers notify different block hashes at the same height
- **THEN** both notifications are recorded independently with their own timestamps

### Requirement: Server metadata collection on connect
The system SHALL query `server.version`, `server.banner`, and `server.donation_address` immediately upon establishing a new connection and record the results.

#### Scenario: Metadata recorded on connect
- **WHEN** a connection to a server is established
- **THEN** all three metadata queries are issued and results stored within 5 seconds

#### Scenario: Missing donation address handled
- **WHEN** a server does not support `server.donation_address`
- **THEN** the field is stored as NULL without failing the connection

### Requirement: Periodic fee data polling
The system SHALL poll `blockchain.estimatefee(n)` for n ∈ {1, 2, 3, 5, 10, 25, 50, 100, 144, 504, 1008}, `blockchain.relayfee`, and `mempool.get_fee_histogram` at configurable intervals (defaults: estimatefee every 60s, histogram every 30s).

#### Scenario: Fee estimate recorded
- **WHEN** a polling cycle fires for a connected server
- **THEN** fee estimates for all configured block targets are stored with timestamp

#### Scenario: Server unavailable during poll
- **WHEN** a server is disconnected when a poll cycle fires
- **THEN** the poll is skipped for that server and no error is recorded

### Requirement: Periodic ping / RTT recording
The system SHALL send `server.ping` to each connected server every 10 seconds and record the round-trip latency in milliseconds.

#### Scenario: RTT recorded
- **WHEN** a ping response is received
- **THEN** `(server_id, timestamp, latency_ms)` is written to the availability table

### Requirement: Uptime/downtime event logging
The system SHALL record a connect event when a server connects and a disconnect event when it drops, including the error reason if available.

#### Scenario: Connect event logged
- **WHEN** a server transitions to connected state
- **THEN** an availability record with `event_type=connect` is written

#### Scenario: Disconnect event logged
- **WHEN** a server transitions to disconnected state
- **THEN** an availability record with `event_type=disconnect` and optional error message is written

### Requirement: Exponential backoff reconnect
The system SHALL reconnect to disconnected servers using exponential backoff with jitter: `delay = min(2^attempt * 2, 300) + uniform(0, 5)` seconds.

#### Scenario: Reconnect attempted after disconnect
- **WHEN** a server disconnects
- **THEN** reconnection is attempted after the computed backoff delay

#### Scenario: Backoff capped
- **WHEN** a server has failed more than 7 consecutive times
- **THEN** reconnect delay does not exceed 300 seconds

### Requirement: Graceful shutdown on SIGINT
The system SHALL catch SIGINT (Ctrl+C) and close all open connections cleanly before exiting, flushing any pending DB writes.

#### Scenario: Ctrl+C triggers shutdown
- **WHEN** the user sends SIGINT
- **THEN** all connections are closed and the process exits within 5 seconds
