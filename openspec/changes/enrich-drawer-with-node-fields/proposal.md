## Why

The node detail drawer currently surfaces only ~7 columns from `nodes` (ip, port, last_seen, asn, country_name, user_agent, is_example) even though the table holds far richer data per node — `version`, `banner`, `risk_level`, `is_dev_version`, `first_seen`, `asn_name`, `city`, `subdivision`, `geo_country_*` (MaxMind), `hostname`, `isp`, `org`, `tags`, `latitude`, `longitude`. The API already returns all of these in `NodeDetailOut`, so the drawer is a frontend-only display gap. Operators inspecting a node need to drop into raw SQL to see the Bitcoin Core version banner or distinguish a dev/RC build, which defeats the purpose of having a detail view.

## What Changes

- Drawer header gains: explicit `version` (with a `DEV` pill when `is_dev_version`), `risk_level` pill, `first_seen` next to `last_seen`, `city`/`subdivision` and the dual-geo split when MaxMind disagrees with Shodan, and `asn_name` next to the ASN number.
- Drawer header gains a row of attribute pills sourced from `tags_json` (e.g. `TOR`, `BITCOIN`) rendered with the existing `Pill` primitive.
- A new **Banner** card in the body renders the raw Shodan banner in a monospaced, pre-formatted block so operators can read protocol-level fields (UA suffix, Lastblock, custom forks like Knots/UASF) without leaving the dashboard.
- The existing **Cross-references** card (currently a stub: "cross-references arrive in a future change") is filled in with rows for ASN+name, ISP, hosting org, hostname, dual-geo (Shodan vs MaxMind), and lat/lon when present. Empty fields are omitted (no `—` placeholder rows).
- The `refs` tab is renamed to `host` to match the operator-meaningful content (network/host metadata, not academic cross-references).

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `dashboard-node-detail-drawer`: header now enumerates version, risk level, dev flag, dual-geo, ASN name, first_seen, and tag pills; body adds a banner card; the cross-references card requirement is filled in concretely; the third tab is renamed from `refs` to `host`.

## Impact

- **Mostly frontend.** Affected files: `frontend/components/explorer/NodeDetailDrawer.tsx`, `frontend/components/ui/Pill.tsx` (extended with `DEV`, `RISK`, `BITCOIN`, `TAG` kinds and a `dim` tone), `frontend/lib/api/types.ts` (banner/lat/lon added to `NodeOut`), and the drawer/table/explorer test files.
- **Tiny backend addition.** `NodeOut` Pydantic model and `_node_out_kwargs` (in `src/web/routers/nodes.py`) gain `banner`, `latitude`, `longitude`. The DB columns already exist; this is purely an API-surface change to expose them. Original proposal incorrectly claimed "no backend change" — corrected during implementation.
- **No database migration.** All fields exist in `nodes` today.
- **Test fixtures**: drawer/table/explorer fixtures gain the three new fields; new drawer tests added for DEV pill, tags, RISK pill, subtitle composition, MaxMind divergence, banner card, host card row filtering, and the `host` tab label.
