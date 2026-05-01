## Purpose

Operator-facing dashboard for inspecting Bitcoin node scan results, triggering scans, and exploring vulnerabilities. Hosted as a Next.js application (post `redesign-dashboard-design-system`) that consumes the FastAPI `/api/v1/*` endpoints.
## Requirements
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

#### Scenario: Country filter combines with risk level filter
- **WHEN** both a risk level and a country are selected
- **THEN** the table shows only nodes matching both filters

### Requirement: Dashboard supports three theme modes
The dashboard SHALL support three theme modes — `dark`, `light`, and `system` — and SHALL apply the resolved theme by setting a `data-theme` attribute on the `<html>` element to either `"dark"` or `"light"`. The `system` mode SHALL resolve at runtime against `window.matchMedia('(prefers-color-scheme: dark)')`. The default mode (when no preference has been stored) SHALL be `system`.

#### Scenario: Default mode is system on first visit
- **WHEN** a user opens the dashboard with no value stored under `localStorage['bns:theme']`
- **THEN** the dashboard SHALL resolve the theme from the operating-system preference and set `<html data-theme="dark">` or `<html data-theme="light">` accordingly

#### Scenario: Stored explicit dark mode is honoured
- **WHEN** `localStorage['bns:theme']` is `"dark"` and the page loads
- **THEN** `<html>` SHALL carry `data-theme="dark"` regardless of the system preference

#### Scenario: Stored explicit light mode is honoured
- **WHEN** `localStorage['bns:theme']` is `"light"` and the page loads
- **THEN** `<html>` SHALL carry `data-theme="light"` regardless of the system preference

### Requirement: Light theme palette is provided
The dashboard SHALL ship a complete light palette covering all 18 colour tokens. The light palette SHALL preserve `primary` as `#F7931A` and `on-primary` as `#0a0a0a` so the brand mark and primary-CTA foreground are identical across themes. Body-text colour pairs (`text` on `bg`, `text-dim` on `bg`, pill foreground on pill background for `alert`/`warn`/`ok`) SHALL meet WCAG AA contrast (≥ 4.5:1).

#### Scenario: Light palette is emitted in globals.css
- **WHEN** `pnpm tokens:gen` runs against the canonical `DESIGN.md`
- **THEN** `frontend/app/globals.css` SHALL contain a `[data-theme="light"]` block (inside the `BEGIN/END GENERATED TOKENS` markers) defining all `--color-*` custom properties, with `--color-bg: #f6f6f6`, `--color-text: #1a1a1a`, `--color-primary: #F7931A`, and `--color-on-primary: #0a0a0a`

#### Scenario: Dark palette remains the :root default
- **WHEN** `pnpm tokens:gen` runs
- **THEN** the `:root` block SHALL still define the dark palette as the fallback (so any DOM with no `data-theme` attribute renders in dark)

### Requirement: Theme codegen exposes a typed themes constant
The token codegen SHALL emit a `themes` constant in `frontend/lib/design-tokens.ts` keyed by mode (`"dark"` and `"light"`), each value containing the full colour map. The pre-existing flat `colors` export SHALL remain available and SHALL equal `themes.dark`, so `tailwind.config.ts` and existing component imports compile unchanged.

#### Scenario: themes.dark equals colors
- **WHEN** the regenerated `design-tokens.ts` is imported
- **THEN** `themes.dark` SHALL deep-equal the `colors` export

#### Scenario: themes.light contains the new palette
- **WHEN** the regenerated `design-tokens.ts` is imported
- **THEN** `themes.light.bg` SHALL equal `"#f6f6f6"` and `themes.light.text` SHALL equal `"#1a1a1a"`

### Requirement: Theme selector lives in the TopNav
The TopNav SHALL render a `ThemeToggle` segmented control with three options (`dark`, `light`, `system`). The currently active option SHALL display the existing primary-underline active treatment used by `Tabs.tsx`. Clicking an option SHALL change the active mode immediately, with no page reload.

#### Scenario: Active mode is highlighted
- **WHEN** the resolved mode is `dark`
- **THEN** the `dark` option in the toggle SHALL carry the `border-b border-primary` underline and the others SHALL not

#### Scenario: Click switches theme without reload
- **WHEN** the user clicks the `light` option while the current mode is `dark`
- **THEN** `<html>` SHALL carry `data-theme="light"`, `localStorage['bns:theme']` SHALL be `"light"`, and the page SHALL not reload

### Requirement: Theme commands available in the command palette
The command palette SHALL register three NAV-kind commands: `theme: dark`, `theme: light`, and `theme: system`. Each command SHALL have `restEndpoint: null` and SHALL invoke the same setter used by `ThemeToggle`.

#### Scenario: Palette command switches mode
- **WHEN** the user opens the command palette and selects `theme: light`
- **THEN** the dashboard SHALL transition to light mode (same observable effect as clicking the `light` option in the TopNav)

#### Scenario: Theme commands pass restEndpoint contract test
- **WHEN** the existing `lib/__tests__/commands.test.ts` walks `COMMAND_SPECS`
- **THEN** the three theme commands SHALL be present, each with `kind === 'NAV'` and `restEndpoint === null`

### Requirement: Theme choice is persisted across reloads
The dashboard SHALL persist the user's selected mode under `localStorage['bns:theme']` with one of the values `"dark"`, `"light"`, or `"system"`. On reload, the persisted value SHALL be re-applied before React hydrates so the page does not flash the wrong theme.

#### Scenario: Reload preserves explicit mode
- **WHEN** the user selects `light` and reloads the page
- **THEN** the page SHALL render with `<html data-theme="light">` from the very first paint (no visible flash of dark)

#### Scenario: localStorage failure does not crash
- **WHEN** `localStorage` access throws (private mode, quota exceeded, or disabled storage)
- **THEN** the dashboard SHALL still render with a sensible default theme (resolved from the system preference) and SHALL NOT raise an unhandled exception

### Requirement: System mode reacts to OS preference changes
While the active mode is `system`, the dashboard SHALL listen to `window.matchMedia('(prefers-color-scheme: dark)')` change events and update `<html data-theme>` live. The listener SHALL be removed when the user selects an explicit `dark` or `light` mode.

#### Scenario: OS toggles to light while in system mode
- **WHEN** the active mode is `system` and the OS preference flips from dark to light
- **THEN** `<html>` SHALL update from `data-theme="dark"` to `data-theme="light"` without any user action

#### Scenario: Switching away from system removes the listener
- **WHEN** the active mode transitions from `system` to `dark`
- **THEN** subsequent OS preference changes SHALL NOT modify `<html data-theme>`


### Requirement: Example nodes are visually distinguished
The dashboard SHALL render nodes whose API payload has `is_example: true` with a dedicated pink/rose `EXAMPLE` badge in the explorer FLAGS column and in the detail drawer header. The badge SHALL be driven exclusively by theme tokens declared in `DESIGN.md` (`color.accent`, `color.accent-bg`, `color.accent-border`) and SHALL be defined for both the `dark` and `light` themes. Components SHALL NOT contain hardcoded hex colors for this accent. The example flag SHALL NOT tint the row background or apply a left border — those visual treatments are reserved for the row-selection state.

#### Scenario: Example row in the node table
- **WHEN** the explorer renders a node whose `is_example` is `true`
- **THEN** the row SHALL include a visible `EXAMPLE` pill rendered with the `accent` tokens, and the row container SHALL carry `data-example="true"` for testability

#### Scenario: Non-example row is unchanged
- **WHEN** the explorer renders a node whose `is_example` is `false`
- **THEN** the row SHALL render exactly as before this change, without an `EXAMPLE` badge and without a `data-example` attribute

#### Scenario: Detail drawer marks example nodes
- **WHEN** the user opens the detail drawer for a node whose `is_example` is `true`
- **THEN** the drawer header SHALL display an `EXAMPLE` badge using the same `accent` tokens, and the header container SHALL carry `data-example="true"` for testability

#### Scenario: Badge works in both themes
- **WHEN** the user toggles between the `dark` and `light` themes via the theme selector
- **THEN** the pink/rose `EXAMPLE` badge SHALL remain visible and contrast-correct in both themes (no token resolves to `transparent` or to the same value as the badge background)

### Requirement: Selected row uses the accent tint
The dashboard's `TableRow` primitive SHALL render the selected state with a `bg-accent-bg` row tint in addition to the existing 2px primary left border. This applies to any row whose `selected` prop is true, regardless of `is_example`.

#### Scenario: Selected row is tinted
- **WHEN** a row is rendered with `selected={true}`
- **THEN** the row container SHALL apply the `bg-accent-bg` Tailwind utility AND the existing 2px primary left border AND carry `data-selected="true"`

#### Scenario: Unselected row has no accent tint
- **WHEN** a row is rendered with `selected={false}` (or omitted)
- **THEN** the row container SHALL NOT apply the `bg-accent-bg` utility

### Requirement: Dashboard hides example nodes on demand
The dashboard SHALL provide a way to hide example nodes from the explorer view, in addition to the default "show everything" behavior. The toggle SHALL pass `is_example=false` to `GET /api/v1/nodes` when active and SHALL omit the parameter when inactive.

#### Scenario: Hide-examples toggle excludes them
- **WHEN** the user activates the hide-examples toggle in the explorer
- **THEN** the dashboard SHALL re-fetch `GET /api/v1/nodes?is_example=false` and the table SHALL no longer display rows with the `EXAMPLE` badge

#### Scenario: Toggle off restores default
- **WHEN** the user deactivates the hide-examples toggle
- **THEN** the dashboard SHALL re-fetch `GET /api/v1/nodes` (without the `is_example` parameter) and example rows SHALL reappear
