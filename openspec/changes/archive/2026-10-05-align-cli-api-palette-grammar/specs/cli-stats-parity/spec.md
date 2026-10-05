## ADDED Requirements

### Requirement: CLI stats command renamed

The database CLI SHALL expose `python -m src.db.cli stats` as the canonical statistics command. The former name `db-stats` SHALL remain as a deprecated alias that produces identical stdout and prints a deprecation warning to stderr, slated for removal in the release after this lands.

#### Scenario: Canonical name

- **WHEN** the operator runs `python -m src.db.cli stats`
- **THEN** the statistics report is printed to stdout and nothing is printed to stderr

#### Scenario: Deprecated alias

- **WHEN** the operator runs `python -m src.db.cli db-stats`
- **THEN** the same report is printed to stdout and a deprecation warning pointing to `stats` is printed to stderr
