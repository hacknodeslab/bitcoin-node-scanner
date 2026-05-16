## Context

The CVE backend is complete: `cve_entries` (NVD-fed catalog) and `node_vulnerabilities` (node↔CVE links). `GET /api/v1/vulnerabilities` (`src/web/routers/vulnerabilities.py`) returns the whole catalog as `VulnerabilitiesOut { total, items: CVEEntryOut[] }` — note `total = len(items)`, it is **not** actually paginated server-side. `GET /api/v1/vulnerabilities/{cve_id}/nodes` returns affected nodes. `VulnerabilityRepository` already has `count_affected_nodes(cve)` and `get_nodes_by_cve(cve)`.

The dashboard (`frontend/`) is currently single-route: `frontend/app/page.tsx` is the explorer. CVE data only appears in `NodeDetailDrawer.tsx`'s "vulnerabilities" tab. `frontend/lib/api/endpoints.ts` already has `getVulnerabilities()`; `types.ts` has `CVEEntryOut`, `VulnerabilitiesOut`, `CVELink`. The `Pill` component has a `kind="CVE"` variant. `NodeTable` has the established sortable/paginated table pattern. The command palette's `vuln.list` (`commands.ts`, group `VULNERABILITIES`, `restEndpoint: "GET /api/v1/vulnerabilities"`) currently just calls `mutate("/api/v1/vulnerabilities")` in `CommandPaletteRoot.tsx`.

## Goals / Non-Goals

**Goals:**
- A `/vulnerabilities` route: sortable, paginated CVE catalog table with affected node count.
- Pivot from a CVE to its affected nodes, and from there into the explorer.
- Reachable from the palette (`vuln.list`) and a persistent nav affordance.
- Reuse the design system, theme, `Pill`, and `NodeTable` patterns.

**Non-Goals:**
- Server-side pagination of the catalog endpoint — the NVD catalog is small (~100 entries); client-side sort/paginate is sufficient. Revisit only if the catalog grows large.
- Editing/triaging CVEs or managing the NVD fetch from the UI — read-only view.
- Changing the `NodeDetailDrawer` CVE tab — it stays as the per-node view.
- A full multi-page nav redesign — add the minimum nav affordance to reach the new page.

## Decisions

**1. Affected node count: one batched aggregate query, added to `CVEEntryOut`.**
Add `affected_node_count` to `CVEEntryOut`. In `get_vulnerabilities`, compute counts with a single `GROUP BY cve` aggregate over `node_vulnerabilities` (active links), then map onto the catalog items — never one query per CVE. Add a `VulnerabilityRepository` helper (e.g. `count_affected_nodes_by_cve()` returning a `{cve_id: count}` map) if a batched variant doesn't already exist. Alternative considered: a separate `/vulnerabilities/counts` endpoint — rejected, the count belongs on the catalog item the table already fetches.

**2. Pivot UI: expandable row, not a new drawer.**
Selecting a CVE row expands it in place to show affected nodes (from `/vulnerabilities/{cve_id}/nodes`). Reusing `NodeDetailDrawer` is wrong (that's per-node, IP-keyed); a second drawer type is more surface than needed. Expandable row keeps the catalog as the spine and the affected-nodes list as a detail. Each affected node links into the explorer with the node selected. Alternative considered: deep-link into the explorer filtered by CVE — rejected for v1 because node-list filtering has no CVE filter yet (would be a bigger change); the explorer link targets the node detail directly.

**3. `vuln.list` becomes a navigation command but keeps its REST mapping.**
Change only the *action* in `CommandPaletteRoot.tsx` from `mutate(...)` to routing to `/vulnerabilities`. Keep the `CommandSpec` `restEndpoint: "GET /api/v1/vulnerabilities"` so the palette-REST parity test still passes — the page genuinely is backed by that endpoint. No `dashboard-command-palette` spec requirement governs command actions, so this needs no delta there; the reachability requirement lives in the new capability.

**4. Client-side sort/paginate, reusing `NodeTable` patterns.**
The page fetches the full catalog once via `getVulnerabilities()` and sorts/paginates client-side, mirroring the table/pagination components the explorer uses. Keeps the implementation small and consistent; consistent with Non-Goal #1.

**5. Routing: add `frontend/app/vulnerabilities/page.tsx`, minimal nav.**
The dashboard gains its second route. Add a persistent nav affordance (header link or similar) so explorer ↔ vulnerabilities is reachable without the palette. Keep it minimal — this is not a nav-system redesign.

## Risks / Trade-offs

- **[Catalog grows and client-side pagination gets slow]** → Acceptable now (~100 entries). If the NVD catalog grows large, add server-side pagination to the endpoint as a follow-up — the table component already has the pagination affordance.
- **[Batched count query drift vs. `NodeDetailDrawer`'s "active link" definition]** → Use the exact same active-link predicate `VulnerabilityRepository` already uses for `get_nodes_by_cve` / `count_affected_nodes`, so the catalog count and the drawer agree.
- **[Adding a second route changes app-shell assumptions]** → Some explorer state lives in `page.tsx`; ensure shared shell (theme provider, layout) stays in `app/layout.tsx` and isn't duplicated. Verify the pre-hydration theme script still applies on the new route.

## Migration Plan

Pure additive change: one new backend field, one new frontend route, one palette action tweak. No DB schema or migration. Deploy is the normal frontend + backend deploy. Rollback is reverting the commit; the `affected_node_count` field is additive so old frontends ignore it.

## Open Questions

- Should the affected-nodes expandable row paginate too, or is it acceptable to show all affected nodes for a CVE inline (some CVEs affect hundreds of nodes)? Leaning toward a capped list with a "view all in explorer" affordance, but the explorer needs a CVE filter for that to be clean — deferred.
