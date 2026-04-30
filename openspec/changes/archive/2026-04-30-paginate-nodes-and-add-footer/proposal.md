## Why

The explorer route currently renders up to 100 node rows in a non-scrolling column, which makes the page taller than the viewport and pushes the existing footer below the fold. The user has to scroll the whole page just to see the keyboard-hint footer, and there is no place to surface where the data comes from or to communicate that the dashboard is for security-research use only. We need a viewport-bounded layout with a paginated node table and a footer that is always visible and carries data-source attribution plus a research-only disclaimer.

## What Changes

- Add explicit pagination controls under the node table: page size, current page indicator, prev/next, total count. Pagination MUST drive the existing `limit`/`offset` query params on `GET /api/v1/nodes`. To render "page X of Y" the backend SHALL also expose the filtered total — added as an `X-Total-Count` response header on `GET /api/v1/nodes` (non-breaking; existing clients can ignore it).
- Constrain the explorer page to the viewport height. The header, query bar, stats strip, and footer SHALL be fixed in vertical space; only the node table area SHALL scroll internally when its rows overflow the available height.
- Replace the current kbd-only footer with a footer that includes (a) a research-only disclaimer, (b) data-source attribution (Shodan, NVD, MaxMind GeoIP), and (c) the existing keyboard hints. The footer MUST remain visible without scrolling on a typical desktop viewport.
- **BREAKING (spec-only)**: The "Footer keyboard hints" requirement in `dashboard-explorer-view` is superseded by a broader "Page footer" requirement that covers disclaimer, sources, and kbd hints together. Existing kbd-hint behavior is preserved as a sub-clause.

## Capabilities

### New Capabilities
<!-- None — the change extends an existing capability. -->

### Modified Capabilities
- `dashboard-explorer-view`: adds a pagination requirement on the node table, adds a viewport-bounded layout requirement, and replaces "Footer keyboard hints" with a broader "Page footer" requirement that covers disclaimer, sources, and kbd hints.
- `web-api`: adds an `X-Total-Count` response header on `GET /api/v1/nodes` reflecting the count of nodes matching the active filters (ignoring `limit`/`offset`).

## Impact

- Mostly frontend. One small, additive backend change: `GET /api/v1/nodes` returns an `X-Total-Count` header (response body unchanged).
- Affected files (indicative):
  - `frontend/components/explorer/NodeTable.tsx` — wire pagination state, replace fixed `limit: 100` fetch with page-driven params, render pagination controls.
  - `frontend/components/explorer/Explorer.tsx` and `frontend/app/page.tsx` — apply viewport-height layout (`100dvh`/`100vh` flex column), make the table area the only scrolling region.
  - `frontend/components/explorer/ExplorerFooter.tsx` — extend with disclaimer + sources blocks; keep kbd hints.
  - `frontend/lib/hooks/use-nodes.ts` — accept/expose `total` count if not already returned (may need a `count` header or a separate `count` endpoint; design.md decides).
- Tests: pagination wiring, viewport layout, footer content (disclaimer text + source links).
- Risk: low. No data-model or API contract changes; the change is layout + UI plumbing.
