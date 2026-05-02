## ADDED Requirements

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
- **THEN** the subtitle SHALL append ` · (MM: France)` after the locality string

### Requirement: Header meta row carries first-seen alongside last-seen

The drawer header meta row (top line) SHALL render `seen <last_seen>` followed by `since <first_seen>` separated by `·`. When `first_seen` is null, that segment SHALL be omitted. When `last_seen` is null, `seen —` SHALL render.

#### Scenario: Both timestamps render

- **WHEN** a node has `last_seen = "2026-04-26T10:00:00Z"` and `first_seen = "2025-11-12T08:30:00Z"`
- **THEN** the header meta row SHALL render `seen 2026-04-26 · since 2025-11-12` (or equivalent locale formatting)

#### Scenario: First-seen omitted when null

- **WHEN** a node has `first_seen = null`
- **THEN** only the `seen <last_seen>` segment SHALL render in the meta row

## MODIFIED Requirements

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
