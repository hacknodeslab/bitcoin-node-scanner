## Why

Users can currently see node data only in the summary table, which truncates most fields. Clicking on an IP should reveal a detail view with the complete raw data we have — both Shodan-sourced fields and MaxMind GeoIP fields — so operators can inspect any node without leaving the dashboard.

## What Changes

- Clicking on any IP address in the node table opens a modal dialog
- The modal displays all available node fields grouped into two sections: **Shodan data** (IP, port, version, protocol, risk level, country, ISP, org, OS, tags, ports, last seen, first seen) and **GeoIP data** (MaxMind country code, country name)
- The modal is dismissable via a close button, the Escape key, or clicking the backdrop
- No new API endpoints are needed — the existing `GET /api/v1/nodes/{node_id}/geo` endpoint is used for GeoIP fields; Shodan fields are already in the node list response

## Capabilities

### New Capabilities
- `node-detail-modal`: A modal dialog on the web dashboard that shows full node details (Shodan + GeoIP) when an IP is clicked

### Modified Capabilities
- `web-dashboard`: IP column cells become clickable links/buttons that trigger the modal

## Impact

- `src/web/static/index.html`: modal HTML + CSS + JS (open/close, fetch geo data, render)
- `src/web/routers/nodes.py`: no change needed (existing `/nodes/{id}/geo` is public and returns geo fields)
- No new dependencies, no backend changes
