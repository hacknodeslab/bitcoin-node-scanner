## Context

The drawer has two information densities: today's stripped-down header (last_seen + ASN number + IP:port + country) and the operator's mental model of "everything we know about this node". The dashboard already pays the network round-trip for `/api/v1/nodes/{id}` (since the recent change that switched the drawer from list-based detail to the dedicated endpoint), so the response payload arrives with `version`, `banner`, `risk_level`, `is_dev_version`, `first_seen`, `asn_name`, `city`, `subdivision`, `geo_country_code`, `geo_country_name`, `hostname`, `isp`, `org`, `tags`, `latitude`, `longitude` — but the React component throws most of them away.

Field-coverage in the production DB (412 nodes today, sampled in our scan):

| Field | Coverage | Source |
|---|---|---|
| `version`, `country_code/name`, `asn`, `asn_name`, `banner`, `risk_level` | 100% | Shodan `api.search()` |
| `latitude`/`longitude` | 99% | Shodan |
| `subdivision` | 57% | Shodan |
| `geo_country_*` | sparse | MaxMind enrichment |
| `hostname`, `isp`, `org`, `tags_json`, `user_agent` | ~1% | Shodan host enrichment (rare) |
| `os_info`, `open_ports_json`, `vulns_json`, `cpe_json` | 0% | Host enrichment (never run) |

Implication: the change should render fields conditionally — fields that are typically empty (`hostname`, `isp`, `org`, `user_agent`, `tags`) must be hidden, not shown as `—`. Fields that are always present (`version`, `country`, `risk_level`) become first-class header citizens.

## Goals / Non-Goals

**Goals:**
- Surface every populated field of `NodeDetailOut` somewhere in the drawer without scrolling for the common case.
- Render the raw banner verbatim in a monospaced block so protocol-level details (Knots fork, UASF, Lastblock, protocol version) are visible without SQL.
- Distinguish Shodan-reported geo from MaxMind-reported geo when they disagree (operationally relevant: ASN-level vs IP-level geolocation can differ).
- Keep the drawer scannable: empty fields are omitted, not rendered as placeholder rows.

**Non-Goals:**
- Backfilling enrichment fields that are 0%/1% populated today — `os_info`, `open_ports_json`, `cpe_json` stay empty until the scanner is changed to call `api.host()`. That is a separate change.
- Adding map rendering for `latitude`/`longitude` in the drawer — defer to a future change that introduces a map widget.
- Showing historical CVE timeline (resolved CVEs, version drift) — out of scope; the drawer keeps the active-CVEs-only view.
- Editing or annotating node metadata in the UI — read-only display.

## Decisions

### 1. Header layout: three-line stack

**Decision**: Keep the three-line header (meta · IP:port · subtitle) but pack more into each line.

- Line 1 (meta, `text-meta` `text-muted`): `seen <last_seen>` · `since <first_seen>` · `<asn> <asn_name>`. Right-anchored close glyph as today.
- Line 2 (title): `IP:port` (port in `text-alert` if `has_exposed_rpc`), `EXAMPLE` pill, `DEV` pill (when `is_dev_version`), `risk_level` pill. Copy-IP button stays on the right of this line.
- Line 3 (`text-meta` `text-muted`): `<version>` · `<city>, <subdivision>, <country_name>` · MaxMind suffix `(MM: <geo_country_name>)` only when `geo_country_code` differs from `country_code`. Then optional `tags_json` rendered as small pills.

**Why not a tabular header?** The drawer width is limited (~50% of viewport on common screens) and a 4-column metadata grid wraps poorly. Three single-line slots with inline separators (`·`) read fast and degrade gracefully when fields are empty (we just drop the `·`-prefixed segment).

**Alternative considered**: a separate "OVERVIEW" tab containing all of this. Rejected — operators don't want to click into a tab to see the version they just opened the drawer to inspect.

### 2. Banner rendering: dedicated card, monospaced, bounded height

**Decision**: Add a `card-banner` between the existing `card-ports` (currently empty) and `card-vulns`. Render `<pre>` with `font-mono`, `text-body-sm`, `whitespace-pre-wrap`, `max-h-[180px]` and `overflow-y-auto`. No syntax highlighting.

**Why a card and not a tab?** The banner is short (typically 4–6 lines, ~150–500 chars) and contextually belongs with the rest of the protocol-level metadata. Putting it behind a tab hides it.

**Why a height cap?** Some banners (custom forks, multi-line UA chains) can be longer; a hard cap with internal scroll prevents the drawer from jumping when switching between nodes via the sliver.

### 3. Cross-references card: filled in, conditional rows

**Decision**: Replace the placeholder text with rows for fields that are populated. Each row is `key (muted) | value (text-dim)` matching the existing spec language. Order: `ASN`, `ISP`, `ORG`, `HOSTNAME`, `GEO (Shodan)`, `GEO (MaxMind)`, `LAT/LON`. Skip any whose value is null/empty.

**Why omit empty rows?** Per Decision 1 and the coverage table — most enrichment fields are sparse. A cross-reference card padded with `—` placeholders makes every node look identically uninformative; skipping fields lets the populated nodes (e.g., the four `is_example` seeds) actually show their richness.

**Why no map?** See Non-Goals.

### 4. Tab rename: `refs` → `host`

**Decision**: The third tab currently labelled `refs` (for "cross-references") becomes `host`. The card label `cross-references` becomes `host metadata`.

**Why?** "refs" is operator-confusing — it suggests external links (RIPE, BGP toolkit) that aren't there. "host" matches the actual content (network/host fields). Aligning the label to the data reduces tab-flipping.

### 5. Tags as pills in the header (not inline strings)

**Decision**: When `tags_json` is non-empty, render each tag as a `Pill` with `kind="GENERIC"` (using a neutral surface tone). Tags `tor` and `bitcoin` get reserved colour mappings to match existing pill conventions (`TOR` → muted blue surface, `BITCOIN` → primary tinted). Other tags render in the generic tone.

**Why pills, not inline text?** Pills are how the dashboard already signals categorical state (`EXPOSED`, `STALE`, `EXAMPLE`, `CVE`). Tags slot into the same visual language. Inline text in line 3 would compete with the version+geo metadata.

## Risks / Trade-offs

- **Risk**: Banner content is user-controlled (Bitcoin nodes can advertise arbitrary UA strings). Rendering it as `<pre>` is safe (React escapes by default) but a malformed UTF-8 banner could break layout.
  → **Mitigation**: backend already truncates banner to 500 chars in `_map_node_data`; React's default escaping handles encoding. Cap visible height with `max-h-[180px]` so a 500-char banner can't push the footer off-screen.

- **Risk**: Header cramming (line 2 + line 3 with multiple pills) could overflow at narrow widths.
  → **Mitigation**: use `flex-wrap` on the pill row; the next line absorbs overflow rather than being truncated. Verify at the existing 720px breakpoint used by the explorer table.

- **Trade-off**: Conditional row rendering means two nodes can have visibly different drawer heights. This is intentional (Decision 3) but operators may prefer a fixed shape.
  → **Mitigation**: not a blocker for v0; revisit if user feedback says otherwise.

- **Risk**: Dual-geo display assumes `country_code` (Shodan) and `geo_country_code` (MaxMind) are comparable. Empty MaxMind fields must not trigger the disagreement branch.
  → **Mitigation**: only render the MaxMind suffix when `geo_country_code` is non-null AND differs from `country_code`. If equal, suppress.
