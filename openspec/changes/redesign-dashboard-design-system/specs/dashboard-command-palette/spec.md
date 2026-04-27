## ADDED Requirements

### Requirement: ⌘K opens the command palette
The dashboard SHALL listen for `⌘K` (macOS) and `Ctrl+K` (other platforms) at the application root and open a command palette overlay. The shortcut SHALL work from any view in the dashboard.

#### Scenario: Shortcut opens palette from explorer
- **WHEN** the user is on the explorer route and presses `⌘K`
- **THEN** the palette SHALL open within 100ms and the input SHALL receive focus

#### Scenario: Shortcut opens palette from drawer
- **WHEN** the user has the node detail drawer open and presses `⌘K`
- **THEN** the palette SHALL open over the drawer and the drawer SHALL remain rendered underneath

### Requirement: Palette overlay uses flat backdrop dimming
When open, the palette SHALL render over a flat `rgba(0,0,0,0.5)` backdrop. The backdrop SHALL NOT use `backdrop-blur`, `backdrop-filter`, or any other glassmorphism effect. The palette panel itself SHALL render on `bg` with a 1px `border` outline.

#### Scenario: Backdrop is flat alpha
- **WHEN** the palette is open
- **THEN** the backdrop element's computed background SHALL equal `rgba(0, 0, 0, 0.5)` and `backdrop-filter` SHALL be `none`

### Requirement: Palette layout
The palette SHALL be a single panel with a maximum width of 560px, a `bg` background, and a 1px `border` outline. It SHALL contain a header input row, a scrollable list of grouped commands, and a footer with keyboard hints (`↑↓ navigate`, `↵ run`, `esc close`).

#### Scenario: Panel max-width is 560px
- **WHEN** the palette is open on a viewport wider than 560px
- **THEN** the panel SHALL render at 560px wide and SHALL be horizontally centred

### Requirement: Input row grammar
The input row SHALL render the `›` prompt glyph in `primary`, followed by the typed query in `text`, followed by a blinking 1px caret. A right-anchored count meta SHALL display the number of matching commands in `dim` colour with `meta` typography.

#### Scenario: Prompt is primary
- **WHEN** the palette opens
- **THEN** the leading `›` glyph SHALL render in `primary` and the typed query area SHALL be empty

#### Scenario: Count updates as user types
- **WHEN** the user types into the input
- **THEN** the right-anchored count SHALL update to reflect the number of matching commands

### Requirement: Grouped commands
Commands SHALL be grouped by category (e.g. `SCAN`, `NODES`, `EXPORT`, `NAV`). Each group SHALL be preceded by a `label` token header (10/500, +0.6 letter-spacing, uppercase) in `dim` colour and SHALL be separated from the previous group by a 1px `border-dim` divider.

#### Scenario: Group label rendered above commands
- **WHEN** the palette renders the `SCAN` group
- **THEN** the group SHALL be preceded by a header reading `SCAN` styled with the `label` typography token in `dim` colour

### Requirement: Focused item visual treatment
The currently focused command SHALL render with a `surface` background and a 2px `primary` left border that absorbs 2px of left padding (so the item content does not shift horizontally relative to non-focused items). All other items SHALL render with a `bg` background and no left border.

#### Scenario: Focused item shifts visually but not horizontally
- **WHEN** an item gains focus
- **THEN** its background SHALL change to `surface`, a 2px `primary` left border SHALL appear, and the item's text content SHALL remain in the same horizontal position relative to the panel

### Requirement: Single-line command items
Every command item SHALL fit on a single line at the standard breakpoint (560px panel width). Multi-line items SHALL NOT be allowed. If the rendered text would overflow, it SHALL be truncated with an ellipsis applied to the rightmost segment.

#### Scenario: Long command label truncates
- **WHEN** a command label is too long for one line at 560px
- **THEN** the label SHALL render with `overflow: hidden`, `white-space: nowrap`, and `text-overflow: ellipsis`

### Requirement: Keyboard navigation
Keyboard navigation SHALL support:
- `↑` / `↓` to move focus between items, wrapping at boundaries
- `↵` to execute the focused command
- `Esc` to close the palette and return focus to the previously focused element
- `⌘K` / `Ctrl+K` while open to close the palette (toggle)

Mouse hover SHALL change the focused item.

#### Scenario: Down arrow advances focus
- **WHEN** the palette is open and the first item is focused
- **THEN** pressing `↓` SHALL move focus to the second item

#### Scenario: Esc returns focus
- **WHEN** the user opens the palette from a focused query bar input and then presses `Esc`
- **THEN** the palette SHALL close and focus SHALL return to the query bar input

### Requirement: Every palette command has a REST endpoint
Every command exposed by the palette outside the `NAV` group SHALL have a corresponding REST endpoint under `/api/v1/*`. Verbs and nouns in the palette grammar SHALL be consistent with the REST surface (e.g. palette `scan: start` ↔ REST `POST /api/v1/scans`). Commands in the `NAV` group SHALL be frontend-only (route navigation, palette/drawer dismissal, clipboard actions) and SHALL be exempt from this requirement.

CLI parity is a design-system goal tracked as debt in a follow-up change (`align-cli-api-palette-grammar`); v0 SHALL NOT block on CLI alignment.

#### Scenario: Non-NAV palette entry without REST counterpart fails CI
- **WHEN** a developer adds a palette command outside the `NAV` group whose target verb does not resolve to a registered REST endpoint
- **THEN** a CI check (palette-REST parity test) SHALL fail with a message naming the offending command

#### Scenario: NAV commands are exempt
- **WHEN** a developer adds a `NAV`-group command such as `drawer: close` or `go: explorer`
- **THEN** the palette-REST parity check SHALL skip it and CI SHALL pass

#### Scenario: V0 command set is the frozen list
- **WHEN** the v0 palette is shipped
- **THEN** it SHALL expose exactly the commands listed under "V0 palette command set" in `design.md` D10, no more and no less; additions SHALL be deferred to follow-up changes

### Requirement: Palette closes on command execution
When the user presses `↵` on a focused command, the palette SHALL execute the command and close itself. Commands that open a sub-surface (e.g. opening the drawer, focusing a query field) SHALL transfer focus to the new surface as part of execution.

#### Scenario: Selecting `node: open` closes palette and opens drawer
- **WHEN** the user activates `node: open <ip>` in the palette
- **THEN** the palette SHALL close, the node detail drawer SHALL open for that IP, and focus SHALL move to the drawer's first focusable element
