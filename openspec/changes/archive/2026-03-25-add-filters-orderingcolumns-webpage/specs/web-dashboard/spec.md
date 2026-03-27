## ADDED Requirements

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
