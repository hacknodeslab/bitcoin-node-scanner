## ADDED Requirements

### Requirement: Example node flag column
The `nodes` table SHALL include an `is_example` column of type `BOOLEAN`, `NOT NULL`, with default `FALSE`, and SHALL be indexed to support efficient `WHERE is_example = ?` filtering.

#### Scenario: Fresh database has the column
- **WHEN** a fresh database is created via SQLAlchemy `Base.metadata.create_all`
- **THEN** the `nodes` table SHALL contain an `is_example` boolean column with `NOT NULL DEFAULT 0` (SQLite) or `NOT NULL DEFAULT FALSE` (PostgreSQL)

#### Scenario: Existing database is upgraded in-place
- **WHEN** the application starts against an existing database whose `nodes` table lacks the `is_example` column
- **THEN** the system SHALL issue an `ALTER TABLE nodes ADD COLUMN is_example BOOLEAN NOT NULL DEFAULT 0` (or PostgreSQL equivalent) and continue startup without manual intervention

#### Scenario: Concurrent startup migrations are serialized
- **WHEN** two processes invoke `init_db()` concurrently against the same PostgreSQL instance
- **THEN** the system SHALL acquire `pg_advisory_xact_lock` before issuing any DDL, hold it for the duration of `Base.metadata.create_all` plus the additive migration, and release it on transaction commit/rollback so only one process runs DDL at a time

#### Scenario: DDL failures fail fast
- **WHEN** `Base.metadata.create_all` or the additive migration raises any exception during `init_db()`
- **THEN** the exception SHALL propagate to the caller (the function MUST NOT log-and-return-False) so the surrounding process can exit instead of continuing against a half-migrated schema

#### Scenario: Index exists for filter queries
- **WHEN** the `nodes` table has been created or upgraded
- **THEN** an index SHALL exist on `is_example` so that `SELECT ... WHERE is_example = false` does not require a full table scan
