## ADDED Requirements

### Requirement: Reputation card
In the `host` tab, below the `host metadata` card, the drawer SHALL render a `REPUTATION` card when `node.reputation` is non-null, and SHALL omit it entirely when `node.reputation` is null or when every row below would be omitted (e.g. all sources failed). The card SHALL use the same row layout as `host metadata` (key in `muted`, value in `text-dim`, 1px `border-dim` dividers) and render, omitting rows whose value is null:

1. `ABUSE SCORE` — a `Pill` with `kind="ABUSE"` showing the score, coloured `alert` when ≥ 75, `warn` when ≥ 25, `ok` when < 25.
2. `REPORTS` — `abuse_total_reports`, followed by `· last <relative time>` when `abuse_last_reported_at` is present.
3. `BLOCKLISTS` — one `Pill` with `kind="BLOCKLIST"` (alert colours) per list id; when `blocklists` is `[]`, the value `none` in `dim`. Each pill whose list id has a known public lookup page SHALL be a link opening that page in a new tab (`target="_blank"`, `rel="noopener noreferrer"`): `spamhaus_drop` → `https://check.spamhaus.org/results/?query=<ip>`, `feodo` → `https://feodotracker.abuse.ch/browse/host/<ip>/`, `tor_exit` → `https://metrics.torproject.org/rs.html#search/<ip>`, `firehol_level1` → the list page `https://iplists.firehol.org/?ipset=firehol_level1` (no per-IP lookup exists). Unknown list ids SHALL render as a plain pill.
4. `ENRICHED` — relative time of `reputation_enriched_at`, followed by `· data may be stale` in `warn` when `reputation.stale` is true.

The card SHALL use only existing design tokens and render correctly in both dark and light themes.

#### Scenario: High abuse score renders alert pill
- **WHEN** `reputation.abuse_confidence_score = 82`
- **THEN** the `ABUSE SCORE` row SHALL render a pill with `text-alert` and `bg-alert-bg`

#### Scenario: Medium abuse score renders warn pill
- **WHEN** `reputation.abuse_confidence_score = 30`
- **THEN** the pill SHALL render with `text-warn` and `bg-warn-bg`

#### Scenario: Blocklist hits render as pills
- **WHEN** `reputation.blocklists = ["feodo", "spamhaus_drop"]`
- **THEN** the `BLOCKLISTS` row SHALL render two `BLOCKLIST` pills labelled `feodo` and `spamhaus_drop`

#### Scenario: Blocklist pill links to its lookup page
- **WHEN** node `1.2.3.4` has `reputation.blocklists = ["spamhaus_drop"]`
- **THEN** the `spamhaus_drop` pill SHALL be a link to `https://check.spamhaus.org/results/?query=1.2.3.4` opening in a new tab

#### Scenario: Unknown list renders without a link
- **WHEN** `reputation.blocklists` contains an id with no known lookup page
- **THEN** its pill SHALL render without a link

#### Scenario: Blocklist-only enrichment hides abuse rows
- **WHEN** `reputation.abuse_confidence_score` is null and `blocklists = []`
- **THEN** the card SHALL render `BLOCKLISTS` and `ENRICHED` rows only

#### Scenario: Stale hint
- **WHEN** `reputation.stale = true`
- **THEN** the `ENRICHED` row SHALL include `· data may be stale` in `warn`

#### Scenario: All sources failed
- **WHEN** `node.reputation` is non-null but has no score, no reports, `blocklists = null`, and no `reputation_enriched_at`
- **THEN** no `REPUTATION` card SHALL be rendered

#### Scenario: Not enriched
- **WHEN** `node.reputation` is null
- **THEN** no `REPUTATION` card SHALL be rendered
