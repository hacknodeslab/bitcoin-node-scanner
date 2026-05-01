## ADDED Requirements

### Requirement: Example node flag column
The `nodes` table SHALL include an `is_example` column of type `BOOLEAN`, `NOT NULL`, with default `FALSE`, and SHALL be indexed to support efficient `WHERE is_example = ?` filtering.

#### Scenario: Fresh database has the column
- **WHEN** a fresh database is created via SQLAlchemy `Base.metadata.create_all`
- **THEN** the `nodes` table SHALL contain an `is_example` boolean column with `NOT NULL DEFAULT 0` (SQLite) or `NOT NULL DEFAULT FALSE` (PostgreSQL)

#### Scenario: Existing database is upgraded in-place
- **WHEN** the application starts against an existing database whose `nodes` table lacks the `is_example` column
- **THEN** the system SHALL issue an `ALTER TABLE nodes ADD COLUMN is_example BOOLEAN NOT NULL DEFAULT 0` (or PostgreSQL equivalent) and continue startup without manual intervention

#### Scenario: Index exists for filter queries
- **WHEN** the `nodes` table has been created or upgraded
- **THEN** an index SHALL exist on `is_example` so that `SELECT ... WHERE is_example = false` does not require a full table scan
