# dashboard-explorer-view Specification

## Purpose
TBD - created by archiving change redesign-dashboard-design-system. Update Purpose after archive.
## Requirements
### Requirement: Explorer is the default route
The dashboard SHALL render the explorer view at the application root (`/`). On a cold visit with no query parameters, the explorer SHALL load and display real data within 200ms of the API response, without an empty hero, illustration, or onboarding overlay.

#### Scenario: Root route renders explorer
- **WHEN** a browser navigates to the dashboard root URL
- **THEN** the response SHALL render the top nav, query bar, stats strip, and node table; no skeletons SHALL persist after the first successful API response

#### Scenario: Empty database shows a single-line empty state
- **WHEN** the database contains zero nodes
- **THEN** the table area SHALL show one short line of text (e.g. `· no nodes yet`) in `dim` colour and SHALL NOT render an illustration

### Requirement: Top nav layout
The explorer SHALL render a top nav containing the brand mark on the left, a horizontal nav with section labels in the middle (`muted` text by default, `text` colour with a 1px `primary` bottom border for the active tab), and a right cluster with a `live` status indicator (`ok` colour) and meta text (`muted`).

#### Scenario: Active tab uses primary underline
- **WHEN** the user is on the explorer route
- **THEN** the `EXPLORER` tab SHALL be styled with `text` colour and a 1px `primary` bottom border; other tabs SHALL be `muted` with no border

### Requirement: Query bar grammar
A query bar SHALL sit beneath the top nav with a `primary`-coloured `›` prompt glyph, followed by parsed `key=value` tokens with controlled colours: keys in `muted`, equals signs in `dim`, values in `text` by default, `ok` (`v-green`) when the value matches an "ok" semantic (e.g. `tor:false`), and `alert` (`v-red`) when the value matches an alert semantic (e.g. `exposed:true`). On the right, the query bar SHALL show match-count meta text in `dim`.

#### Scenario: Alert value renders red
- **WHEN** the query contains `exposed=true`
- **THEN** the value SHALL render in `alert` colour while the key remains `muted`

#### Scenario: Match count is right-anchored
- **WHEN** the query bar is rendered
- **THEN** the match count meta SHALL sit at the right edge with `dim` colour and `meta` typography (11/400)

### Requirement: 5-tile stats strip
A stats strip with exactly 5 tiles SHALL sit between the query bar and the table, separated by 1px `border` lines. Each tile SHALL render a `label` token header (10/500, +0.6 letter-spacing, uppercase) and a `mono-num` value (16/500), optionally followed by a delta in 10/400. Delta colour SHALL follow the rule that "rising EXPOSED is bad" — a positive delta on a count whose increase is undesirable SHALL render in `alert`, not `ok`.

#### Scenario: Stats strip renders five tiles
- **WHEN** the explorer is rendered
- **THEN** the stats strip SHALL contain five `<StatTile>` elements with 1px `border` separators

#### Scenario: Rising EXPOSED count shows alert delta
- **WHEN** the EXPOSED tile reports `+3`
- **THEN** the delta text SHALL render in `alert`, not `ok`

### Requirement: Dense node table
The table SHALL use 9px vertical padding and 14px horizontal padding for rows. Columns SHALL be a single 7-track grid: chevron, IP+host, port, version, location, last-seen, status pill. Header row SHALL use `label` typography in `dim` colour. Body rows SHALL use `body-sm` typography. Row hover SHALL NOT change the row background.

#### Scenario: Row padding matches token
- **WHEN** a node row is rendered
- **THEN** computed `padding-top` and `padding-bottom` SHALL each equal `9px`

#### Scenario: Hover does not change background
- **WHEN** the user hovers a row
- **THEN** the row's `background-color` SHALL remain `bg`

### Requirement: Inline row expansion with state-coloured left border
Clicking a row's chevron SHALL expand it inline. The expanded row SHALL switch its background to `surface` and gain a 2px left border in the row's state colour (`alert` for EXPOSED rows, `warn` for TOR rows, `dim` for OK rows). The expanded body SHALL render exposure findings, CVEs, and action buttons indented with 32px left padding to anchor under the chevron column.

#### Scenario: Expanded EXPOSED row shows alert left border
- **WHEN** the user expands a row whose status pill is EXPOSED
- **THEN** the expanded container SHALL render with `background: surface` and a 2px solid `alert` left border

#### Scenario: Findings section shows action buttons including L402
- **WHEN** the expanded row contains premium content
- **THEN** the action row SHALL include zero or more `button-secondary` actions on the left and exactly one right-anchored `button-l402` button

### Requirement: Footer keyboard hints
The explorer SHALL render a bottom footer strip with `meta` typography in `dim` colour, listing keyboard hints (e.g. `⌘K command palette`, `↵ open detail`, `/ focus query`). Each kbd token SHALL render with a `surface-2` background.

#### Scenario: ⌘K hint visible in footer
- **WHEN** the explorer is rendered
- **THEN** the footer SHALL include a kbd-styled `⌘K` token followed by the label `command palette`

### Requirement: Risk-level filter
The explorer SHALL provide a risk-level filter that re-fetches `GET /api/v1/nodes?risk_level=<value>` and updates the table. The filter UI SHALL be expressed through the query bar grammar (e.g. `risk:critical`), not a separate dropdown.

#### Scenario: Setting risk in query bar refetches
- **WHEN** the user types or selects `risk=critical` in the query bar
- **THEN** the dashboard SHALL fetch `/api/v1/nodes?risk_level=critical` and re-render the table

### Requirement: Country filter
The explorer SHALL provide a country filter populated from `GET /api/v1/nodes/countries`. Like the risk filter, it SHALL be expressed through the query bar grammar (e.g. `country:DE`).

#### Scenario: Country token narrows results
- **WHEN** the user adds `country=DE` to the query
- **THEN** the table SHALL show only nodes whose Server Location is Germany

#### Scenario: Country and risk combine
- **WHEN** both `risk=high` and `country=DE` are present
- **THEN** the table SHALL show only nodes matching both filters

### Requirement: Sortable columns
Each non-status column header SHALL be activatable. Activating a header SHALL sort by that column ascending; activating again SHALL toggle to descending. The active sort column SHALL render its name suffixed with a glyph: `›` rotated 90° via the `Glyph` component (or the dedicated `caret` glyph) for descending, the same glyph mirrored for ascending. Inactive columns SHALL show a `dim` `·` glyph as a quiet hint.

#### Scenario: Activate header sorts
- **WHEN** the user activates the `LAST SEEN` header
- **THEN** the table SHALL reload sorted by `last_seen` and the header SHALL show the descending glyph

#### Scenario: Re-activate toggles direction
- **WHEN** the user activates an already-active sort header
- **THEN** the sort direction SHALL invert and the table SHALL reload

### Requirement: Trigger scan from the explorer
The explorer SHALL expose a scan-trigger affordance via the command palette (`scan: start`) and via a row in the explorer's action footer or query bar. The trigger SHALL `POST /api/v1/scans` and SHALL be disabled while a scan is `pending` or `running`. While disabled, it SHALL render with `dim` text and SHALL show the current job status.

#### Scenario: Scan trigger disabled while running
- **WHEN** a scan job is in `running` state
- **THEN** the scan trigger SHALL be disabled and SHALL display the running status text

#### Scenario: Successful trigger starts polling
- **WHEN** the user activates the scan trigger and the API returns 202
- **THEN** the dashboard SHALL poll `GET /api/v1/scans/{job_id}` every 10 seconds until the job reaches `completed` or `failed`

### Requirement: Stats auto-refresh
The explorer SHALL re-fetch `GET /api/v1/stats` every 30 seconds while the tab is foreground. The refresh SHALL update the stats strip without a full page reload and SHALL respect the rule that a "live" indicator (`ok` colour) flickers briefly when an update lands.

#### Scenario: Stats refresh updates tiles
- **WHEN** 30 seconds elapse since the last stats fetch and the tab is foreground
- **THEN** the dashboard SHALL re-fetch `/api/v1/stats` and update the five tiles in place

#### Scenario: Background tab pauses refresh
- **WHEN** the dashboard tab is hidden for 60 seconds
- **THEN** stats SHALL NOT be re-fetched until the tab regains foreground

