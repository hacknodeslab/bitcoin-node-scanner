## Context

The dashboard already fetches node list data (`GET /api/v1/nodes`) which includes Shodan-sourced fields. The `GET /api/v1/nodes/{node_id}/geo` endpoint (now public) returns MaxMind GeoIP fields. The frontend is a single `index.html` with inline CSS and JS — no build step, no framework.

## Goals / Non-Goals

**Goals:**
- Click on any IP cell → open a modal with full Shodan + GeoIP data for that node
- Modal shows all available fields, labelled and grouped
- Modal closes on: close button, Escape key, backdrop click
- No additional backend changes

**Non-Goals:**
- Edit/modify node data from the modal
- Deep-link to a node detail page (URL routing)
- Lazy-loading additional Shodan API data not already in DB

## Decisions

**D1 — Use node data already in the list response for Shodan fields**
The list response includes all Shodan fields stored in the DB. No extra API call is needed for Shodan data. Only the GeoIP fields require a second request (`GET /api/v1/nodes/{id}/geo`), which is already public.

Alternative: add a `GET /api/v1/nodes/{id}` detail endpoint. Rejected — unnecessary backend work; the list already returns full data.

**D2 — Modal rendered with inline HTML/CSS in the single-file dashboard**
Consistent with the existing single-file architecture. No framework dependency.

**D3 — GeoIP fields fetched on modal open (lazy)**
We fetch `/api/v1/nodes/{id}/geo` when the modal opens, not on page load. Avoids N extra requests for the full page and keeps geo data fresh.

**D4 — Node ID passed via data attribute on the IP cell**
Each `<td>` for the IP column gets `data-node-id="<id>"`. The click handler reads this attribute and passes it to the modal open function.

## Risks / Trade-offs

- [Risk] GeoIP fetch fails or is slow → Show "Loading…" then "Unavailable" on error — no spinner needed
- [Trade-off] Modal fetches geo on every open → Acceptable; the endpoint is lightweight and data rarely changes

## Migration Plan

1. Update `index.html` — add modal HTML, CSS, JS, and click handlers on IP cells
2. No backend deployment needed — existing public endpoint is sufficient
3. Rollback: revert `index.html`
