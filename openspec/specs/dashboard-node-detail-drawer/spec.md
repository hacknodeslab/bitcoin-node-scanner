# dashboard-node-detail-drawer Specification

## Purpose
TBD - created by archiving change redesign-dashboard-design-system. Update Purpose after archive.
## Requirements
### Requirement: Drawer opens on row activation
The dashboard SHALL open a node detail drawer when the user activates a node row in the explorer table (via mouse click on the row body, `↵` on a focused row, or via the command palette `node: open <ip>` command). The drawer SHALL be rendered as an overlay over the explorer; the explorer SHALL remain mounted underneath.

#### Scenario: Click on row opens drawer
- **WHEN** the user clicks the body of a node table row
- **THEN** the drawer SHALL open for that node within 100ms and SHALL load detail data from `GET /api/v1/nodes/{ip}`

#### Scenario: Drawer closes via close glyph
- **WHEN** the user clicks the `✗` glyph in the drawer header
- **THEN** the drawer SHALL close and focus SHALL return to the originating row

### Requirement: Drawer layout — sliver + main panel
The drawer SHALL render a two-column layout: a 180px-wide left **sliver** of recent nodes (rendered at 0.45 opacity, with the active node row at full opacity) and a flexible-width **main panel** to the right. The two columns SHALL be separated by a 1px `border` line.

#### Scenario: Sliver renders recent nodes at 0.45 opacity
- **WHEN** the drawer opens
- **THEN** the sliver SHALL list up to 10 recent nodes with each row at `opacity: 0.45`, except the active node which SHALL render at full opacity with a `surface` background and a 2px `primary` left border

### Requirement: Drawer header
The drawer header SHALL render:
- A meta row with key/value pairs (`label` token in `dim` colour for keys, `meta` typography in `muted` for values) and a right-anchored close `✗` glyph
- An IP address line in `title` typography (17/500). When a port is exposed, the port number SHALL render in `alert` colour after the IP separated by `:`. A `copy` action SHALL appear after the address in `dim` colour.
- A subtitle in `meta` typography and `muted` colour describing the host (e.g. ASN, location).

#### Scenario: Exposed port renders in alert
- **WHEN** the node has an exposed RPC port
- **THEN** the port number in the address line SHALL render in `alert` colour

#### Scenario: Close glyph in header
- **WHEN** the drawer header is rendered
- **THEN** a right-anchored `✗` glyph in `dim` colour SHALL be present and activatable

### Requirement: Tabs row
Below the header, the drawer SHALL render a horizontal tabs strip with `meta` typography. The active tab SHALL render in `text` colour with a 1px `primary` bottom border; inactive tabs SHALL render in `muted` with no border. Tabs SHALL include count badges where appropriate; counts SHALL render in `dim` by default and in `alert` when the count represents a security finding (e.g. `CVES (3)` where 3 are unresolved).

#### Scenario: Active tab uses primary underline
- **WHEN** the user is on the `OVERVIEW` tab
- **THEN** that tab SHALL render in `text` colour with a 1px `primary` bottom border absorbing the row's bottom border

#### Scenario: CVE count renders alert when nonzero
- **WHEN** the `CVES` tab shows three unresolved CVEs
- **THEN** the count `(3)` SHALL render in `alert` colour

### Requirement: Open ports card
The drawer body SHALL render an `OPEN PORTS` card. Each row SHALL be a 3-column grid: port number (`title` weight, `body-sm` size) on the left, description (`text-dim`) in the middle, status text on the right. Status text SHALL use a state colour (`t-red` / `t-amber` / `t-green` / `t-dim`) and the `label` typography token (10/500, +0.3 letter-spacing).

#### Scenario: Exposed port row uses red status
- **WHEN** an open ports row corresponds to an exposed RPC port
- **THEN** the right-side status text SHALL render in `alert` colour

### Requirement: Vulnerabilities card
The drawer body SHALL render a `VULNERABILITIES` card listing CVEs detected for the node. Each entry SHALL show the CVE id (in `text`), a CVSS or severity tag rendered as a `Pill` with `kind="CVE"` and the appropriate `severity` discriminator, and a single-line description in `dim` colour using `meta` typography.

#### Scenario: High-severity CVE renders alert pill
- **WHEN** a CVE entry has `severity="high"`
- **THEN** its `Pill` SHALL render with `text-alert` and `bg-alert-bg`

#### Scenario: No CVEs renders ok pill
- **WHEN** the node has zero CVEs
- **THEN** the card body SHALL contain a single row showing `<Pill kind="OK" />` and a `dim` line `· no CVEs detected`

### Requirement: Cross-references card
The drawer body SHALL render a `CROSS-REFERENCES` card showing externally reachable identifiers for the node (ASN, hosting provider, geo). Each row SHALL be a 2-column flex layout with the key in `muted` and the value in `text-dim`, separated by 1px `border-dim` dividers.

#### Scenario: ASN row renders
- **WHEN** the node has ASN data
- **THEN** the cross-references card SHALL include a row whose key is `ASN` (in `muted`) and whose value is the ASN number and organisation name (in `text-dim`)

### Requirement: Drawer footer with action row
The drawer footer SHALL render an action row: a left cluster of `button-secondary` actions (e.g. `copy ip`, `view in shodan`, `re-scan`) and a single right-anchored `button-l402` button when premium content is available for the node. The L402 button SHALL be prefixed with the `⚡` glyph and SHALL be the only loud-coloured element in the drawer.

#### Scenario: L402 button right-anchored
- **WHEN** premium content is available for the node
- **THEN** the L402 button SHALL be the rightmost element in the footer action row, with `button-l402` styling and a `⚡` prefix

#### Scenario: No premium content hides L402 button
- **WHEN** the node has no premium content available
- **THEN** the footer SHALL omit the L402 button entirely; placeholders SHALL NOT be rendered

### Requirement: L402 click target follows the standard 402 challenge convention
Activating the L402 button SHALL fetch the protected resource the button is bound to. The backend SHALL respond with HTTP `402 Payment Required` and a `WWW-Authenticate: L402 macaroon="<value>", invoice="<value>"` header. In v0 the macaroon and invoice fields are placeholder strings clearly marked as such; the response body SHALL include `{"error": "l402_pending"}`. The frontend, lacking a payment client in v0, SHALL detect any `402` whose `WWW-Authenticate` header begins with `L402 ` and SHALL display a non-blocking inline note (`meta` typography, `dim` colour) next to the button without raising a modal.

#### Scenario: 402 with L402 challenge shows inline note
- **WHEN** the user activates the L402 button and the API returns `402` with `WWW-Authenticate: L402 macaroon="...", invoice="..."`
- **THEN** the drawer SHALL render an inline `· l402 not yet available` note next to the button and SHALL NOT show a modal or alert

#### Scenario: V0 button is bound to the example endpoint
- **WHEN** the v0 dashboard renders the L402 button in the drawer
- **THEN** activation SHALL target `GET /api/v1/l402/example` (the placeholder protected resource) until subsequent changes bind the button to specific premium content

### Requirement: Drawer is keyboard-navigable
The drawer SHALL trap focus while open. `Tab` and `Shift+Tab` SHALL cycle focus through interactive elements within the drawer. `Esc` SHALL close the drawer. Activating a sliver row SHALL load that node's detail without dismissing the drawer.

#### Scenario: Esc closes drawer
- **WHEN** the drawer is open and the user presses `Esc`
- **THEN** the drawer SHALL close and focus SHALL return to the row that opened it

#### Scenario: Sliver row swaps detail in place
- **WHEN** the user activates a different node in the sliver
- **THEN** the main panel SHALL re-render for the new node and the drawer SHALL remain open

