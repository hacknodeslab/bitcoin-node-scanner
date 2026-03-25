## Why

The web dashboard table currently shows nodes in a fixed order with only a risk-level filter. Users cannot sort by any column or filter beyond risk level, making it hard to investigate specific patterns (e.g., find the most recently seen critical nodes, or browse nodes by country).

## What Changes

- Add column sorting (clickable headers) for: IP, Port, Version, Risk Level, Server Location, IP Registry, Last Seen
- Add additional filter controls: country (server location), ASN/IP Registry country
- Extend the `/api/v1/nodes` endpoint to accept `sort_by`, `sort_dir`, and `country` query parameters
- Update the frontend to wire sorting headers and the new filter dropdowns to the API

## Capabilities

### New Capabilities
- `node-list-filtering`: Filter nodes by risk level and country (server location) via API query params
- `node-list-sorting`: Sort the node list by any column via API query params, with ascending/descending toggle

### Modified Capabilities
- `web-dashboard`: Table gains sortable headers and additional filter dropdowns
- `web-api`: `/api/v1/nodes` gains `sort_by`, `sort_dir`, and `country` query params

## Impact

- `src/web/routers/nodes.py`: extend `list_nodes` with new query params and SQLAlchemy `order_by`
- `src/web/static/index.html`: sortable `<th>` elements, country filter dropdown, JS state for sort column/direction
- No schema changes required — sorting and filtering operate on existing columns
