## Context

The explorer route renders the node table at `frontend/components/explorer/NodeTable.tsx` with a hardcoded `limit: 100`, no scroll container, and no page controls. The page itself is a normal document flow, so the table grows the page height without bound and pushes `ExplorerFooter` (currently kbd-only) below the fold. The user has no way to (a) move past the first 100 rows, (b) see the footer without scrolling the whole page, or (c) discover where the data comes from / that it is research-only.

Backend already supports `limit` (1–1000) and `offset` (≥0) on `GET /api/v1/nodes` (`src/web/routers/nodes.py:153`). It does NOT currently surface the filtered total — neither in the body nor as a header — so a "page X of Y" indicator is not buildable client-side without an additional round-trip or a header.

## Goals / Non-Goals

**Goals:**
- The explorer page MUST fit within the viewport on a typical desktop (≥768px height): nav + query bar + stats strip stay pinned at top, the footer stays pinned at bottom, and only the node-table region scrolls when its rows overflow.
- The node table MUST be paginated with explicit prev/next controls and a page-size selector. The current page, total pages, and total result count MUST be visible.
- The footer MUST always be visible and MUST contain (a) a research-only disclaimer, (b) data-source attribution, and (c) the existing kbd hints. Disclaimer and sources MUST be screen-reader accessible.

**Non-Goals:**
- No infinite scroll, no virtualization. Pagination is offset-based; rows per page is bounded so DOM size stays small.
- No URL-based pagination state (`?page=N`) in this change. State is component-local; deep-linking can come later.
- No mobile-specific layout. The viewport-bounded layout targets desktop; small-screen behavior degrades to natural scrolling and is out of scope.
- No new API endpoints. The only backend change is an `X-Total-Count` response header on the existing `GET /api/v1/nodes`.

## Decisions

### Decision 1: Offset-based pagination with `X-Total-Count` header

**Choice:** Drive pagination from the existing `limit`/`offset` query params on `GET /api/v1/nodes`. Add an `X-Total-Count` response header carrying the count of nodes matching the active filters (ignoring `limit`/`offset`). Page size: 25 default, selectable from {25, 50, 100}.

**Rationale:** The endpoint already accepts `limit`/`offset`. A header-only addition is non-breaking — existing clients ignore unknown headers. Computing the filtered total reuses the same `WHERE` clause SQLAlchemy already builds for the row query (one extra `count()` call per request, microseconds on the indexed columns we filter by).

**Alternatives considered:**
- *Body envelope `{ items, total }`:* breaks the current `List[NodeOut]` contract and every client that uses it. Rejected.
- *Separate `GET /api/v1/nodes/count` endpoint:* needs a parallel filter parser, doubles round-trips per page change. Rejected.
- *Cursor pagination (no total):* simpler but loses "page X of Y" and direct page-jump. Worse UX for a research tool where users want to know how many results they're paging through. Rejected.
- *Virtualized infinite scroll:* solves height but loses the discoverable "this is the end" signal and complicates the footer-always-visible requirement. Rejected.

### Decision 2: Viewport-bounded layout via flex column with `100dvh`

**Choice:** Wrap the explorer in a single full-height flex column: `<header>`, `<main>` (table area, `flex-1 min-h-0 overflow-y-auto`), `<footer>`. Use `100dvh` rather than `100vh` so mobile browser chrome doesn't clip content.

**Rationale:** Single source of truth for vertical sizing. The `min-h-0` on the scrolling child is the standard fix to let a flex child shrink below its content size, which is what makes `overflow-y-auto` actually scroll inside the parent rather than overflowing the viewport.

**Alternatives considered:**
- *CSS Grid with `grid-template-rows: auto auto auto 1fr auto`:* equivalent outcome but harder to debug when rows have implicit heights. Flex is closer to how the existing components are styled.
- *`position: sticky` footer:* still allows the page to grow taller than the viewport. Doesn't satisfy the goal that the footer is always visible without page scroll.

### Decision 3: Footer is one requirement, three sections

**Choice:** Replace the current "Footer keyboard hints" requirement with a single "Page footer" requirement that mandates three semantic sections in a single `<footer>` element: kbd hints (preserved), data-source attribution (Shodan, NVD, MaxMind GeoIP), and a research-only disclaimer. Layout: kbd hints left, sources center, disclaimer right on wide screens; stack vertically below ~640px.

**Rationale:** A single footer requirement is easier to reason about than three separate ones. Composing the three sections in one element lets us keep the footer to two compact lines on desktop without exceeding the existing `meta` typography budget.

**Alternatives considered:**
- *Three separate requirements:* fragments behavior the user always sees together. Slightly cleaner spec but harder to coordinate visual layout decisions.
- *Move disclaimer to a modal / "About" page:* hides the legal/ethics signal that the user explicitly asked to be visible. Rejected.

### Decision 4: Page-size and filter changes reset to page 1

**Choice:** Any change to `limit` (page size) or to active filters (`risk_level`, `country`, `exposed`, `tor`) resets `offset` to 0. Sort-direction or sort-column changes likewise reset to page 1.

**Rationale:** Standard pagination convention. Avoids the surprising state where a user changes a filter and lands on an out-of-range page with zero results.

## Risks / Trade-offs

- **[Risk] `count()` on filtered query under high node counts** → Mitigation: indexed columns (`risk_level`, `country_name`, `has_exposed_rpc`) make this O(index scan). Current dataset is in the low thousands; if it grows large enough to matter we add a cached count, but that's premature now.
- **[Risk] Viewport-bounded layout truncates the table on very short windows (e.g., 500px tall)** → Mitigation: enforce a minimum visible height (e.g., 3 rows) on the scrolling region; below that, allow the page to scroll naturally so nothing becomes unreachable.
- **[Risk] Mobile/narrow layout regressions** → Mitigation: footer stacks below ~640px; pagination controls collapse to prev/next + "page X of Y" without the page-size selector. Explicit out-of-scope: no responsive redesign beyond what is needed to keep the footer reachable.
- **[Trade-off] Adding `X-Total-Count` couples the API and the client to this header** → Acceptable: it is a widely-used convention and additive. If we later switch to body envelope we keep the header for a deprecation period.

## Migration Plan

1. Backend: extend `list_nodes` to compute the filtered total and set `X-Total-Count` on the response. Cover with a unit test that asserts the header value matches the count of rows that would be returned without `limit`/`offset`.
2. Frontend: extend `useNodes` to read `X-Total-Count` (the typed `request` helper in `frontend/lib/api/client.ts` already reads the `Response` object — confirm and extend if it currently discards headers).
3. Frontend: introduce pagination state in `NodeTable` (page, pageSize) and render `<Pagination>` controls under the table.
4. Frontend: refactor the explorer shell to a `100dvh` flex column with a scrolling table region; verify the footer is visible without page scroll on a 768px-tall viewport.
5. Frontend: extend `ExplorerFooter` with disclaimer + sources sections; preserve kbd hints.
6. No data migrations; no rollback steps beyond reverting the commits.

## Open Questions

- Does the existing `request` helper in `frontend/lib/api/client.ts` expose response headers, or does it return only the parsed body? If only the body, we extend it to optionally return `{ data, headers }` for endpoints that need it. Decided during implementation.
- ~~Exact disclaimer wording.~~ **Resolved:** "For security research and educational purposes only. Information is provided as-is; do not use for unauthorized access."
