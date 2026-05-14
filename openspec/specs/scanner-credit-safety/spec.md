# scanner-credit-safety Specification

## Purpose

Protects Shodan API credits from being drained by a single scan run. The scanner's per-query pagination is bounded by predictable termination conditions, each run enforces a configurable query-credit budget ceiling, and the end-of-run summary reports the real number of query credits consumed (derived from pages fetched). Project documentation also makes clear that running the scanner writes JSON/CSV output only and that `db-import` must be run to persist results to the database.

## Requirements

### Requirement: Bounded pagination

The scanner's per-query pagination loop SHALL terminate after a finite, predictable number of `api.search()` calls. The loop MUST stop when any of the following holds: the collected count reaches the configured `max_results`, the collected count reaches Shodan's reported `total`, a fetched page returns zero matches, or the page index exceeds `ceil(total / 100)`.

#### Scenario: Page returns zero matches

- **WHEN** a paginated `api.search()` call returns an empty `matches` list
- **THEN** the scanner stops paginating that query immediately and does not request further pages

#### Scenario: Shodan total overestimates retrievable results

- **WHEN** Shodan reports `total` higher than the number of results actually returned across pages
- **THEN** the scanner stops once `ceil(total / 100)` pages have been requested, even if `collected` is still below `total`

#### Scenario: Normal completion within result set

- **WHEN** a query has fewer results than `max_results` and every page returns matches
- **THEN** the scanner paginates exactly `ceil(total / 100)` times and then stops

### Requirement: Per-scan query-credit budget guard

The scanner SHALL enforce a configurable ceiling on the number of Shodan query credits a single scan run may consume. The ceiling is read from an optional environment variable (`MAX_QUERY_CREDITS_PER_SCAN`). Before each `api.search()` call, the scanner MUST check the credits consumed so far in the run against this ceiling.

#### Scenario: Budget ceiling reached mid-scan

- **WHEN** the credits consumed in the current scan run reach the configured ceiling
- **THEN** the scanner aborts the remaining queries cleanly, logs a WARNING explaining the budget was reached, and proceeds to persist/report whatever was collected so far

#### Scenario: No ceiling configured

- **WHEN** `MAX_QUERY_CREDITS_PER_SCAN` is not set
- **THEN** the scanner applies a safe default ceiling rather than running unbounded

#### Scenario: Scan completes under budget

- **WHEN** a scan finishes all queries having consumed fewer credits than the ceiling
- **THEN** the scanner completes normally with no budget-related warning

### Requirement: Accurate credit-usage reporting

The scanner's end-of-run credit summary SHALL report the actual number of Shodan query credits consumed by the run, derived from the number of pages fetched, not a per-query call count.

#### Scenario: Multi-page scan reports real consumption

- **WHEN** a scan fetches 89 pages across its queries
- **THEN** the credit-usage summary reports approximately 89 query credits used, not the count of distinct queries issued

### Requirement: Documented DB persistence behavior

The project documentation SHALL state that running `python -m src.scanner` (including `--quick`) writes JSON/CSV output only and does not persist results to the database, and that `db-import` must be run to load the results.

#### Scenario: Operator consults documentation after a scan

- **WHEN** an operator runs a scan and checks `CLAUDE.md` for how results reach the database
- **THEN** the documentation directs them to run `db-import` on the generated JSON file
