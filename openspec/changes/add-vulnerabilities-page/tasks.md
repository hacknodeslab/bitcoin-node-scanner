## 1. Backend — affected node count on the catalog

- [x] 1.1 Add a `VulnerabilityRepository` helper that returns a `{cve_id: active_node_count}` map in one `GROUP BY` query over `node_vulnerabilities` (active links), reusing the same active-link predicate as `get_nodes_by_cve`
- [x] 1.2 Add `affected_node_count: int` to the `CVEEntryOut` model and populate it in `get_vulnerabilities` from the batched map (no per-CVE query)
- [x] 1.3 Add/extend a backend test asserting `GET /api/v1/vulnerabilities` items include `affected_node_count` with correct values (including 0 for an unlinked CVE)

## 2. Frontend — API + types

- [x] 2.1 Add `affected_node_count` to the `CVEEntryOut` type in `frontend/lib/api/types.ts`
- [x] 2.2 Confirm `getVulnerabilities()` in `frontend/lib/api/endpoints.ts` returns the new field; add an `getAffectedNodes(cveId)` endpoint call for `GET /api/v1/vulnerabilities/{cve_id}/nodes` if not already present
- [x] 2.3 Run `pnpm typecheck` in `frontend/` after the type change

## 3. Frontend — the vulnerabilities page

- [x] 3.1 Create `frontend/app/vulnerabilities/page.tsx` rendering the CVE catalog as a table (severity via `Pill kind="CVE"`, CVE id linked to NVD, CVSS score, published date, affected versions, affected node count)
- [x] 3.2 Make the table sortable (severity, CVSS, published date, affected node count) and paginated, reusing the `NodeTable` table/pagination patterns
- [x] 3.3 Add an empty state for a catalog with no entries
- [x] 3.4 Implement the expandable-row pivot: selecting a CVE fetches and shows its affected nodes (`GET /api/v1/vulnerabilities/{cve_id}/nodes`), each node linking into the explorer's node detail view
- [x] 3.5 Ensure the page uses the design-system tokens and works in both dark and light theme (verify the pre-hydration theme script applies on the new route)

## 4. Navigation wiring

- [x] 4.1 Change the `vuln.list` action in `frontend/components/explorer/CommandPaletteRoot.tsx` from `mutate(...)` to navigating to `/vulnerabilities`; keep the `CommandSpec.restEndpoint` unchanged in `frontend/lib/commands.ts`
- [x] 4.2 Add a persistent dashboard nav affordance linking explorer ↔ `/vulnerabilities`
- [x] 4.3 Confirm the palette-REST parity test (`commands.test.ts`) still passes

## 5. Verification

- [x] 5.1 Add a frontend test for the vulnerabilities page: renders catalog rows, sorts by affected node count, and expands a row to show affected nodes (mocked API)
- [x] 5.2 Run `pnpm typecheck && pnpm test` in `frontend/` and the backend suite `python -m pytest tests/ -v`; confirm no new failures
- [x] 5.3 Manually verify in the browser: navigate via palette and nav link, sort/paginate, expand a CVE, click through to a node — verified by operator after backend restart (affected_node_count) and Explorer useEffect fix for `?ip=` deep links

## 6. Follow-up fixes from manual testing

- [x] 6.1 Drawer showed "node not found" for any IP outside the most-recent 1000 (`getNodeByIp` was scanning, not filtering) — added `ip=` filter to `GET /api/v1/nodes` (mirror of the `port` filter) and switched `getNodeByIp` to use it, with a backend test
