## MODIFIED Requirements

### Requirement: Dashboard served at root URL
The system SHALL serve the dashboard as a Next.js (App Router) application living in the `frontend/` directory of this monorepo, reachable at `FRONTEND_ORIGIN` (default `http://localhost:3000`). The dashboard SHALL no longer be served as a static HTML file by FastAPI; instead, `GET /` on the FastAPI app responds with a 302 redirect to `FRONTEND_ORIGIN` for a 30-day deprecation window, after which the route is removed. The Next.js application SHALL consume the FastAPI `/api/v1/*` endpoints over HTTP, with CORS configured to allow the dashboard origin.

#### Scenario: Frontend runs independently in dev
- **WHEN** a developer runs `pnpm --filter frontend dev` and the FastAPI server is running on port 8000
- **THEN** the dashboard SHALL be reachable at `http://localhost:3000` and SHALL successfully fetch data from `http://localhost:8000/api/v1/*` without CORS errors

#### Scenario: FastAPI redirects root requests
- **WHEN** the FastAPI app receives `GET /`
- **THEN** the server SHALL respond with `302 Found` and a `Location` header pointing at `FRONTEND_ORIGIN`

#### Scenario: Static HTML file is removed
- **WHEN** the change is merged
- **THEN** `src/web/static/index.html` SHALL no longer exist in the repository and any FastAPI `StaticFiles` mount that referenced it SHALL be removed

### Requirement: Dashboard displays scan statistics
The dashboard SHALL fetch and display aggregate statistics from `GET /api/v1/stats` on page load and refresh every 30 seconds while the tab is foreground. Statistics SHALL be rendered in the explorer's 5-tile stats strip per the design system, using the `mono-num` typography token for values and the `label` typography token for tile headers.

#### Scenario: Stats displayed on load
- **WHEN** the dashboard is loaded
- **THEN** the stats strip SHALL show total node count, breakdown by risk level (CRITICAL/HIGH/MEDIUM/LOW), and the timestamp of the last scan, each in a 5-tile strip with 1px `border` separators

#### Scenario: Stats auto-refresh
- **WHEN** 30 seconds have elapsed since the last stats fetch and the tab is foreground
- **THEN** the dashboard SHALL automatically re-fetch `/api/v1/stats` and update the displayed tiles in place

#### Scenario: Background tab pauses refresh
- **WHEN** the tab is hidden
- **THEN** the dashboard SHALL pause the 30-second refresh until the tab regains foreground

### Requirement: Dashboard displays node table
The dashboard SHALL fetch and display a paginated table of nodes from `GET /api/v1/nodes`. The table SHALL render in the explorer view with 9px row padding and 7-column grid layout (chevron, IP+host, port, version, location, last-seen, status pill) per the design system.

#### Scenario: Node table renders on load
- **WHEN** the dashboard is loaded
- **THEN** the explorer SHALL display a table with the columns: chevron, IP+host, port, version, location, last-seen, status pill

#### Scenario: Risk level filter applied
- **WHEN** the user sets `risk:<level>` in the query bar
- **THEN** the dashboard SHALL re-fetch `/api/v1/nodes?risk_level=<level>` and update the table

### Requirement: Trigger scan from dashboard
The dashboard SHALL provide an affordance to trigger a new scan via `POST /api/v1/scans`. The trigger SHALL be exposed both via the command palette (`scan: start`) and via a row-level action in the explorer footer or query bar. The affordance SHALL be disabled while a scan is `pending` or `running`.

#### Scenario: Scan triggered from palette
- **WHEN** the user activates `scan: start` in the command palette and no scan is currently running
- **THEN** the dashboard SHALL `POST /api/v1/scans` and SHALL begin polling `GET /api/v1/scans/{job_id}` every 10 seconds

#### Scenario: Scan trigger disabled while running
- **WHEN** a scan job is in `pending` or `running` state
- **THEN** the trigger SHALL be disabled, render with `dim` text, and display the current scan status

### Requirement: Sortable table headers
Each non-status column header in the node table SHALL be activatable. Activation SHALL toggle ascending/descending sort by that column. The active sort column SHALL render its name suffixed with a `caret` glyph indicating direction; inactive columns SHALL render a `·` glyph in `dim` as a quiet hint. Custom Unicode arrows (▲, ▼, ⇅) SHALL NOT be used; iconography SHALL come from the allow-list defined in the design system spec.

#### Scenario: Activation sorts by column
- **WHEN** the user activates the `LAST SEEN` header
- **THEN** the table reloads sorted by `last_seen` and the header renders the descending caret glyph

#### Scenario: Re-activation reverses order
- **WHEN** the user activates an already-active sort header
- **THEN** the sort direction SHALL invert and the table SHALL reload

### Requirement: Country filter dropdown
A country filter SHALL be present in the explorer and SHALL be populated from `GET /api/v1/nodes/countries`. The filter SHALL be expressed through the query bar grammar (e.g. `country:DE`), not a separate dropdown component, while still presenting a typeahead of distinct country values to the user.

#### Scenario: Country token narrows results
- **WHEN** the user adds `country=DE` to the query bar
- **THEN** the table reloads showing only nodes whose Server Location is Germany

#### Scenario: Country and risk combine
- **WHEN** both `risk=high` and `country=DE` are present in the query bar
- **THEN** the table SHALL show only nodes matching both filters

#### Scenario: Country values come from the API
- **WHEN** the query bar suggests country values
- **THEN** the suggestion list SHALL be drawn from `GET /api/v1/nodes/countries` and SHALL contain all distinct countries currently in the database
