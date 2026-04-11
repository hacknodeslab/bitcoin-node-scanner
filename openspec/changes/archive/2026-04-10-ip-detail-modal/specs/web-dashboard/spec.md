## MODIFIED Requirements

### Requirement: IP cells are clickable
The IP address cells in the node table SHALL be rendered as clickable elements (styled as links) that trigger the node detail modal.

#### Scenario: IP cell has pointer cursor and link style
- **WHEN** user hovers over an IP address in the table
- **THEN** the cursor changes to pointer and the IP is visually highlighted as interactive

#### Scenario: Clicking IP opens detail modal
- **WHEN** user clicks an IP address cell
- **THEN** the node detail modal opens for that node
