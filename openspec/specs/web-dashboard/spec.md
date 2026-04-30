## ADDED Requirements

### Requirement: Dashboard served at root URL
The system SHALL serve a single-page HTML dashboard at `GET /` that loads without a build step.

#### Scenario: Dashboard loads in browser
- **WHEN** a browser navigates to `http://<host>:<port>/`
- **THEN** the server SHALL return a valid HTML page with status 200

### Requirement: Dashboard displays scan statistics
The dashboard SHALL fetch and display aggregate statistics from `GET /api/v1/stats` on page load and refresh every 30 seconds.

#### Scenario: Stats displayed on load
- **WHEN** the dashboard page is loaded
- **THEN** it SHALL show total node count, breakdown by risk level (CRITICAL/HIGH/MEDIUM/LOW), and timestamp of last scan

#### Scenario: Stats auto-refresh
- **WHEN** 30 seconds have elapsed since the last stats fetch
- **THEN** the dashboard SHALL automatically re-fetch `/api/v1/stats` and update the display without a full page reload

### Requirement: Dashboard displays node table
The dashboard SHALL fetch and display a paginated table of nodes from `GET /api/v1/nodes`.

#### Scenario: Node table renders on load
- **WHEN** the dashboard page is loaded
- **THEN** it SHALL display a table with columns: IP, Port, Version, Risk Level, Country, Last Seen

#### Scenario: Risk level filter applied
- **WHEN** the user selects a risk level from a filter dropdown
- **THEN** the dashboard SHALL re-fetch `/api/v1/nodes?risk_level=<selected>` and update the table

### Requirement: Trigger scan from dashboard
The dashboard SHALL provide a button to trigger a new scan via `POST /api/v1/scans`.

#### Scenario: Scan triggered from UI
- **WHEN** user clicks "Start Scan" and no scan is running
- **THEN** the dashboard SHALL POST to `/api/v1/scans`, show a "Scan running..." status indicator, and poll the job status every 10 seconds

#### Scenario: Scan button disabled while scan is running
- **WHEN** a scan job is in `pending` or `running` state
- **THEN** the "Start Scan" button SHALL be disabled and show current scan status

### Requirement: Sortable table headers
Each column header in the node table SHALL be clickable. Clicking a header sorts by that column ascending; clicking again toggles to descending. The active sort column SHALL display ▲ (asc) or ▼ (desc). Inactive columns SHALL display a dim ⇅ hint.

#### Scenario: Click header sorts by that column
- **WHEN** user clicks the "Last Seen" column header
- **THEN** the table reloads sorted by `last_seen` and the header shows ▼

#### Scenario: Second click on same header reverses order
- **WHEN** user clicks an already-active sort header
- **THEN** sort direction toggles and the table reloads

### Requirement: Country filter dropdown
A dropdown filter for "Server Location" (country) SHALL be present in the toolbar. It SHALL be populated from `GET /api/v1/nodes/countries`. Selecting a country filters the table; selecting the blank option clears the filter.

#### Scenario: Dropdown shows available countries
- **WHEN** the page loads
- **THEN** the country dropdown contains all distinct countries from the database

#### Scenario: Selecting a country filters the table
- **WHEN** user selects "Germany" from the country dropdown
- **THEN** the table reloads showing only nodes with Server Location = Germany

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
