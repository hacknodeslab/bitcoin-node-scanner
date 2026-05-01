## ADDED Requirements

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
