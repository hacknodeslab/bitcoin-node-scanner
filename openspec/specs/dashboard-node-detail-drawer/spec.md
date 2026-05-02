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
- A meta row in `meta` typography (`muted` colour) with `seen <last_seen>` and (when present) `since <first_seen>`, followed by `<asn> <asn_name>`. A right-anchored close `✗` glyph SHALL terminate the row.
- An IP address line in `title` typography (17/500). When a port is exposed, the port number SHALL render in `alert` colour after the IP separated by `:`. A `copy` action SHALL appear after the address in `dim` colour. The IP line SHALL be followed by an inline pill row carrying (in order, omitting empties): `EXAMPLE`, `DEV`, the `risk_level` pill, and one pill per `tags` entry.
- A subtitle in `meta` typography and `muted` colour composed of `version`, locality (`city, subdivision, country_name`), and the MaxMind divergence suffix when applicable, separated by `·`.

#### Scenario: Exposed port renders in alert
- **WHEN** the node has an exposed RPC port
- **THEN** the port number in the address line SHALL render in `alert` colour

#### Scenario: Close glyph in header
- **WHEN** the drawer header is rendered
- **THEN** a right-anchored `✗` glyph in `dim` colour SHALL be present and activatable

#### Scenario: Header packs version, locality, and pills for a fully-described node
- **WHEN** a node has version, country/city/subdivision, ASN with name, both timestamps, `is_dev_version=true`, `tags=["bitcoin"]`, and `risk_level="MEDIUM"`
- **THEN** the header SHALL render the meta row, the IP line with `EXAMPLE`/`DEV`/`MEDIUM`/`BITCOIN` pills (skipping `EXAMPLE` if `is_example=false`), and the subtitle with version + locality

### Requirement: Header meta row carries first-seen alongside last-seen
The drawer header meta row (top line) SHALL render `seen <last_seen>` followed by `since <first_seen>` separated by `·`. When `first_seen` is null, that segment SHALL be omitted. When `last_seen` is null, `seen —` SHALL render.

#### Scenario: Both timestamps render
- **WHEN** a node has `last_seen = "2026-04-26T10:00:00Z"` and `first_seen = "2025-11-12T08:30:00Z"`
- **THEN** the header meta row SHALL render `seen 2026-04-26 · since 2025-11-12` (or equivalent locale formatting)

#### Scenario: First-seen omitted when null
- **WHEN** a node has `first_seen = null`
- **THEN** only the `seen <last_seen>` segment SHALL render in the meta row

### Requirement: Header pill row exposes risk level, dev flag, and tags
The drawer header pill row (the row that already carries the `EXAMPLE` pill) SHALL additionally render:
- A `risk_level` pill mapping `node.risk_level` to the standard `Pill` `severity` discriminator (`CRITICAL → critical`, `HIGH → high`, `MEDIUM → medium`, `LOW → low`).
- A `DEV` pill when `node.is_dev_version === true`.
- One `Pill` per entry in `node.tags`. Tags `tor` and `bitcoin` SHALL use reserved colour mappings (TOR → muted blue surface, BITCOIN → primary tinted); other tags SHALL render in a neutral generic tone.

The pill row SHALL use `flex-wrap` so overflow drops to a new line rather than truncating.

#### Scenario: HIGH-risk node renders an alert-tone risk pill
- **WHEN** a node has `risk_level = "HIGH"`
- **THEN** the header SHALL render a pill bound to the `high` severity styling alongside the IP/port

#### Scenario: Dev version pill renders only when flag is set
- **WHEN** a node has `is_dev_version = true`
- **THEN** a `DEV` pill SHALL appear in the header pill row
- **AND WHEN** a node has `is_dev_version = false`
- **THEN** no `DEV` pill SHALL appear

#### Scenario: Tags render as pills, including reserved tags
- **WHEN** a node has `tags = ["bitcoin", "tor"]`
- **THEN** the header SHALL render two pills, one for each tag, with `TOR` using the reserved blue tone and `BITCOIN` using the primary tone

### Requirement: Header subtitle line carries version, locality, and MaxMind divergence
The drawer header subtitle line (third visual line, below IP:port) SHALL render the following segments separated by `·` (middle dot in `text-dim`), in this order, omitting any segment whose source field is null/empty:

1. `node.version` (e.g., `Satoshi:29.3.0`).
2. Locality string composed of `city`, `subdivision`, `country_name`, joined by commas, omitting null parts.
3. MaxMind divergence suffix `(MM: <geo_country_name>)` SHALL render only when `node.geo_country_code` is non-null AND not equal to `node.country_code`. When MaxMind matches Shodan or MaxMind data is absent, this suffix SHALL be suppressed.

#### Scenario: Version-only subtitle when geo is missing
- **WHEN** a node has `version = "Satoshi:25.1.0"`, `country_name = null`, `city = null`
- **THEN** the subtitle SHALL render `Satoshi:25.1.0` with no leading `·`

#### Scenario: Full subtitle with locality
- **WHEN** a node has `version = "Satoshi:29.0.0"`, `country_name = "United States"`, `city = "Reston"`, `subdivision = "Virginia"`, `geo_country_code = "US"`, `country_code = "US"`
- **THEN** the subtitle SHALL render `Satoshi:29.0.0 · Reston, Virginia, United States` and SHALL NOT render a MaxMind suffix

#### Scenario: MaxMind divergence is shown when country differs
- **WHEN** a node has `country_code = "DE"` (Shodan) and `geo_country_code = "FR"` `geo_country_name = "France"` (MaxMind)
- **THEN** the subtitle SHALL append `· (MM: France)` after the locality string

### Requirement: Tabs row
Below the header, the drawer SHALL render a horizontal tabs strip with `meta` typography. The active tab SHALL render in `text` colour with a 1px `primary` bottom border; inactive tabs SHALL render in `muted` with no border. Tabs SHALL include count badges where appropriate; counts SHALL render in `dim` by default and in `alert` when the count represents a security finding (e.g. `CVES (3)` where 3 are unresolved).

#### Scenario: Active tab uses primary underline
- **WHEN** the user is on the `OVERVIEW` tab
- **THEN** that tab SHALL render in `text` colour with a 1px `primary` bottom border absorbing the row's bottom border

#### Scenario: CVE count renders alert when nonzero
- **WHEN** the `CVES` tab shows three unresolved CVEs
- **THEN** the count `(3)` SHALL render in `alert` colour

### Requirement: Banner card surfaces the raw Shodan banner
The drawer body SHALL render a `BANNER` card above the tabs row (always visible regardless of the active tab). The card body SHALL render the value of `node.banner` inside a `<pre>` element using monospaced typography (`font-mono`, `text-body-sm`), `whitespace: pre-wrap`, and a maximum height of `180px` with internal vertical scroll. When `node.banner` is null or empty, the card SHALL be omitted entirely (no placeholder row).

#### Scenario: Banner card renders the multi-line banner verbatim
- **WHEN** a node has `banner = "Bitcoin:\n  User-Agent: /Satoshi:29.3.0/Knots:20260210/UASF-BIP110:0.4/\n  Version: 70016\n  Lastblock: 942053"`
- **THEN** the `BANNER` card SHALL render with each line preserved (newlines respected) inside a monospaced block

#### Scenario: Banner card hidden when banner is empty
- **WHEN** a node has `banner = null`
- **THEN** the drawer body SHALL NOT render a `BANNER` card

#### Scenario: Long banner scrolls within the card
- **WHEN** a node banner exceeds the 180px height budget of the card
- **THEN** the card SHALL scroll vertically inside its own bounds without resizing the drawer

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
The drawer body SHALL render a card surfacing host- and network-level metadata for the node. The tab triggering this card SHALL be labelled `host`; the card label SHALL be `host metadata`. Each row SHALL be a 2-column flex layout with the key in `muted` and the value in `text-dim`, separated by 1px `border-dim` dividers. The card SHALL render rows in this order, omitting any row whose source field is null/empty:

1. `ASN` — `<asn> <asn_name>` when `asn_name` present, else `<asn>` alone.
2. `ISP` — `node.isp`.
3. `ORG` — `node.org`.
4. `HOSTNAME` — `node.hostname`.
5. `GEO (Shodan)` — `<city>, <subdivision>, <country_name>` (omitting null parts), or `<country_name>` alone when finer fields missing.
6. `GEO (MaxMind)` — `<geo_country_name>` rendered only when `geo_country_code` is non-null.
7. `LAT/LON` — `<latitude>, <longitude>` rendered when both are non-null.

When all rows would be omitted (a node with no ASN, no geo, no hostname, etc.), the card SHALL render a single `dim` line `· no host metadata available`.

#### Scenario: ASN row renders with name when present
- **WHEN** the node has `asn = "AS3320"` and `asn_name = "Deutsche Telekom AG"`
- **THEN** the host card SHALL include a row whose key is `ASN` (in `muted`) and whose value is `AS3320 Deutsche Telekom AG` (in `text-dim`)

#### Scenario: Empty fields are omitted, not rendered as placeholders
- **WHEN** the node has `asn = "AS22773"`, `asn_name = "Cox Communications"`, `country_name = "United States"`, but `isp = null`, `org = null`, `hostname = null`
- **THEN** the host card SHALL render only the `ASN` and `GEO (Shodan)` rows; no `ISP`, `ORG`, or `HOSTNAME` row SHALL appear

#### Scenario: MaxMind row only renders when MaxMind data is present
- **WHEN** the node has `geo_country_code = null`
- **THEN** the host card SHALL NOT include a `GEO (MaxMind)` row regardless of Shodan country presence

#### Scenario: Tab label is `host`
- **WHEN** the drawer renders its tabs row
- **THEN** the third tab SHALL display the label `host` (not `refs`)

#### Scenario: Empty card renders a single dim line
- **WHEN** the node has all host-metadata source fields null
- **THEN** the card SHALL render exactly one `dim` `meta`-typography line `· no host metadata available`

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

