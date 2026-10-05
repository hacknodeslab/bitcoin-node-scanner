# cli-path-confinement Specification

## Purpose

Prevents commands driven by an automated agent (or any untrusted source of command-line arguments) from reading or writing files outside the project's data directories. Every file path taken from a command line is resolved and required to sit under one of two operator-configured roots: `INPUT_DIR` (default `data`) for scanner inputs and `OUTPUT_DIR` (default `output`) for scanner dumps.

## Requirements

### Requirement: Input files confined to INPUT_DIR
The `--ips` list, the Nostr relay list, and the nostr.watch export read by `extract_relays` (and the relay list it writes) SHALL be resolved — collapsing `..`, `~`, absolute paths and symlinks — and SHALL be refused unless the resolved path is inside `INPUT_DIR` (default `data`). Read paths SHALL also be existing regular files no larger than 50 MB.

#### Scenario: File inside data/
- **WHEN** `python -m src.scanner --ips data/peers/peers.txt` runs
- **THEN** the list SHALL be read normally

#### Scenario: System file
- **WHEN** `--ips /etc/hosts` is given
- **THEN** the command SHALL fail with a one-line error naming `INPUT_DIR`, without reading the file or performing any lookup

#### Scenario: Symlink escape
- **WHEN** the path is a symlink inside `data/` pointing to a file outside it
- **THEN** it SHALL be refused

### Requirement: Dumps confined to OUTPUT_DIR
`db-import` (file or `--dir`), `db-import-nostr`, `scripts/backfill_import_scan.py`, and the Nostr scanner's `--json` output SHALL only read or write paths that resolve inside `OUTPUT_DIR` (default `output`). Dump reads SHALL be regular files no larger than 500 MB.

#### Scenario: Import outside output/
- **WHEN** `db-import-nostr /etc/hosts` is run
- **THEN** it SHALL exit with status 1 and an error naming `OUTPUT_DIR`, importing nothing

#### Scenario: Write target outside output/
- **WHEN** the Nostr scanner runs with `--json ~/.bashrc`
- **THEN** it SHALL refuse before writing anything

### Requirement: Roots set only by the operator's environment
The roots SHALL be read from the `INPUT_DIR` / `OUTPUT_DIR` environment variables (with the defaults above) and SHALL NOT be overridable by a command-line argument.

#### Scenario: Custom input location
- **WHEN** `INPUT_DIR=/srv/lists` is set and `--ips /srv/lists/peers.txt` is given
- **THEN** the list SHALL be read
