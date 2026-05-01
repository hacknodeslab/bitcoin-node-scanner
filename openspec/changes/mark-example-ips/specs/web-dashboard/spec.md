## ADDED Requirements

### Requirement: Example nodes are visually distinguished
The dashboard SHALL render nodes whose API payload has `is_example: true` with a dedicated pink/rose accent in both the explorer table and the node detail drawer. The accent SHALL be driven exclusively by theme tokens declared in `DESIGN.md` (e.g., `color.example-bg`, `color.example-fg`, `color.example-border`) and SHALL be defined for both the `dark` and `light` themes. Components SHALL NOT contain hardcoded hex colors for this accent.

#### Scenario: Example row in the node table
- **WHEN** the explorer renders a node whose `is_example` is `true`
- **THEN** the row SHALL apply the `color.example-*` tokens (e.g., a pink/rose row tint and border) and SHALL include a visible badge with the text `EXAMPLE`

#### Scenario: Non-example row is unchanged
- **WHEN** the explorer renders a node whose `is_example` is `false`
- **THEN** the row SHALL render exactly as before this change, without any pink/rose accent or `EXAMPLE` badge

#### Scenario: Detail drawer marks example nodes
- **WHEN** the user opens the detail drawer for a node whose `is_example` is `true`
- **THEN** the drawer header SHALL display an `EXAMPLE` badge using the same token-driven accent

#### Scenario: Accent works in both themes
- **WHEN** the user toggles between the `dark` and `light` themes via the theme selector
- **THEN** the pink/rose accent on example rows SHALL remain visible and contrast-correct in both themes (no token resolves to `transparent` or to the same value as the row background)

### Requirement: Dashboard hides example nodes on demand
The dashboard SHALL provide a way to hide example nodes from the explorer view, in addition to the default "show everything" behavior. The toggle SHALL pass `is_example=false` to `GET /api/v1/nodes` when active and SHALL omit the parameter when inactive.

#### Scenario: Hide-examples toggle excludes them
- **WHEN** the user activates the hide-examples toggle in the explorer
- **THEN** the dashboard SHALL re-fetch `GET /api/v1/nodes?is_example=false` and the table SHALL no longer display rows with the `EXAMPLE` badge

#### Scenario: Toggle off restores default
- **WHEN** the user deactivates the hide-examples toggle
- **THEN** the dashboard SHALL re-fetch `GET /api/v1/nodes` (without the `is_example` parameter) and example rows SHALL reappear
