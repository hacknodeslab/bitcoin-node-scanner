## Why

The scanner already collects rich Shodan data (`hostnames`, `os`, `vulns`, `cpe`, `isp`, `org`, `transport`) and the enrichment step fetches the full host scan (`all_ports`, `all_services` with product/version per port, `tags`). None of this is persisted — it is discarded after risk scoring. The node detail modal has nothing to show beyond the bare Bitcoin fields. Users need to see the full picture: open ports, detected OS, CVEs, hostnames, ISP.

## What Changes

- Add columns to the `Node` model: `hostname`, `os_info`, `isp`, `org`, `open_ports_json` (JSON list of `{port, transport, service, product, version}`), `vulns_json` (JSON list of CVE IDs), `tags_json` (JSON list of Shodan tags), `cpe_json` (JSON list)
- Persist these fields in `scanner_integration.py` from the parsed node data
- Extend `parse_node_data` in `scanner.py` to include `os` and `tags` from the base Shodan result (always available, not just for critical nodes)
- Store enrichment `all_services`, `os`, `tags`, `vulns` in the node record when enrichment runs
- Expose new fields in `NodeOut` and `NodeGeoOut` (web API)
- Show them in the node detail modal (Shodan section)
- Add Alembic migration for the new columns

## Capabilities

### New Capabilities
- `shodan-enrichment-storage`: Persist Shodan host enrichment data (ports, OS, CVEs, hostnames, ISP, org, tags) in the Node DB record and expose it via the API and modal

### Modified Capabilities
- `database-storage`: Node model gains new nullable JSON/text columns for enrichment data
- `web-api`: `NodeOut` includes new enrichment fields
- `web-dashboard`: Node detail modal shows OS, hostnames, open ports table, CVEs, ISP, org, tags

## Impact

- `src/db/models.py`: new columns on `Node`
- `migrations/versions/006_add_enrichment_fields.py`: Alembic migration
- `src/scanner.py`: `parse_node_data` captures `os`, `tags` from base result
- `src/db/scanner_integration.py`: persists new fields on upsert; applies enrichment dict to node
- `src/web/routers/nodes.py`: `NodeOut` extended
- `src/web/static/index.html`: modal Shodan section updated
- No new dependencies
