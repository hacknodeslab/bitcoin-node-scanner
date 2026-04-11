## ADDED Requirements

### Requirement: Modal opens on IP click
When a user clicks an IP address in the node table, the dashboard SHALL display a modal dialog with full details for that node.

#### Scenario: Click opens modal
- **WHEN** user clicks on an IP address cell in the node table
- **THEN** a modal dialog appears with the node's details

#### Scenario: Modal shows Shodan fields
- **WHEN** the modal is open
- **THEN** it displays all Shodan-sourced fields: IP, port, version, protocol, risk level, country (Shodan), ISP, org, OS, tags, open ports, first seen, last seen — each with a clear label

#### Scenario: Modal shows GeoIP fields
- **WHEN** the modal is open
- **THEN** it fetches and displays MaxMind GeoIP fields (country code, country name) labelled as "IP Registry"

#### Scenario: GeoIP loading state
- **WHEN** the GeoIP fetch is in progress
- **THEN** the GeoIP section shows "Loading…"

#### Scenario: GeoIP unavailable
- **WHEN** the GeoIP fetch fails or returns no data
- **THEN** the GeoIP section shows "Unavailable"

### Requirement: Modal is dismissable
The modal SHALL be closeable via three interactions.

#### Scenario: Close button dismisses modal
- **WHEN** user clicks the close button (×) inside the modal
- **THEN** the modal closes

#### Scenario: Escape key dismisses modal
- **WHEN** the modal is open and user presses the Escape key
- **THEN** the modal closes

#### Scenario: Backdrop click dismisses modal
- **WHEN** user clicks outside the modal content area (on the backdrop)
- **THEN** the modal closes
