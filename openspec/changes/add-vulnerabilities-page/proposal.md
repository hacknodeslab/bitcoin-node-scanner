## Why

The CVE feature works end-to-end on the backend (`GET /api/v1/vulnerabilities` catalog, `GET /api/v1/vulnerabilities/{cve_id}/nodes` affected nodes) but the dashboard only surfaces CVEs per-node, buried in the `NodeDetailDrawer` "vulnerabilities" tab. There is no way to browse the CVE catalog or answer "which CVE affects the most nodes" — users expect a vulnerabilities page and there isn't one. The `vuln: list` palette command implies a destination that doesn't exist (it only refreshes the SWR cache).

## What Changes

- New route `frontend/app/vulnerabilities/page.tsx`: a sortable, paginated table of the CVE catalog — columns: severity, CVE id (links out to NVD), CVSS score, published date, affected versions, and **affected node count**.
- Clicking a CVE row reveals its affected nodes (expandable row or a side panel) sourced from `GET /api/v1/vulnerabilities/{cve_id}/nodes`, with each node clickable to deep-link into the explorer / node detail drawer.
- The `vuln.list` palette command becomes a real navigation command to `/vulnerabilities` (keeps its `GET /api/v1/vulnerabilities` REST mapping, so the palette-REST parity test stays green). A header/nav affordance also links to the page.
- Backend: `GET /api/v1/vulnerabilities` catalog items gain an `affected_node_count` field so the table can show it without N+1 per-CVE calls.
- The page reuses the existing design system: DESIGN.md tokens, dark/light theme, the `Pill` `kind="CVE"` component, and the table/pagination patterns from `NodeTable`.

## Capabilities

### New Capabilities
- `dashboard-vulnerabilities-view`: A dedicated dashboard page that lists the CVE catalog and lets the user pivot from a CVE to its affected nodes.

### Modified Capabilities
- `web-api`: the `GET /api/v1/vulnerabilities` catalog response gains a per-CVE `affected_node_count` field.

(The `vuln.list` palette command's action changes from cache-refresh to route-navigation, but no `dashboard-command-palette` requirement governs command *actions* — the palette-reachability of the new page is specified under `dashboard-vulnerabilities-view` instead.)

## Impact

- **Frontend**: new `frontend/app/vulnerabilities/page.tsx` and supporting components; `frontend/lib/commands.ts` + `frontend/components/explorer/CommandPaletteRoot.tsx` (vuln.list action); `frontend/lib/api/endpoints.ts` / `types.ts` (`affected_node_count` on `CVEEntryOut`); a nav/header link. Reuses `Pill`, table/pagination patterns, theme tokens.
- **Backend**: `src/web/routers/vulnerabilities.py` (`get_vulnerabilities` adds `affected_node_count`), `src/db/repositories/vulnerability_repository.py` (a count-affected-per-CVE query — `count_affected_nodes` already exists, may need a batched variant to avoid N+1).
- **Routing**: the dashboard stops being strictly single-page — `frontend/app/` gains a second route. Navigation between explorer and vulnerabilities needs a home.
- **No DB schema changes** — `cve_entries` and `node_vulnerabilities` already hold everything needed.
