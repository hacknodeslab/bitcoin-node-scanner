## 1. Backend: X-Total-Count header

- [x] 1.1 In `src/web/routers/nodes.py::list_nodes`, build the filter `WHERE` clause once and reuse it for both the row query and a `select(func.count()).select_from(Node).where(...)` total query
- [x] 1.2 Set `Response.headers["X-Total-Count"]` (FastAPI `Response` injected dependency) to the integer total, on every successful path including the empty-result case
- [x] 1.3 Add a unit test in `tests/test_web_api.py` covering: unfiltered total, filtered total (`risk_level=CRITICAL`), zero-result total, and that the header is a string-encoded integer
- [x] 1.4 Verify CORS exposes the header to the browser: add `X-Total-Count` to `expose_headers` in the CORS middleware in `src/web/main.py`

## 2. Frontend API client: surface response headers

- [x] 2.1 Inspect `frontend/lib/api/client.ts` to confirm whether `request<T>` currently returns parsed body only or also exposes headers
- [x] 2.2 If headers are not exposed, extend `request` to optionally return `{ data, headers }` (e.g., a second overload `requestWithHeaders<T>`) without breaking existing call sites
- [x] 2.3 Update `frontend/lib/api/endpoints.ts::listNodes` (or add a sibling) to return the parsed `NodeOut[]` plus the parsed `X-Total-Count` integer
- [x] 2.4 Update unit tests in `frontend/lib/__tests__/api-client.test.ts` to cover the headers-exposing path

## 3. Frontend hook: useNodes returns total

- [x] 3.1 Extend `frontend/lib/hooks/use-nodes.ts` (or its caller) to include `total: number | null` alongside `nodes`, populated from the `X-Total-Count` header
- [x] 3.2 Update any existing consumers that destructure the hook to ignore `total` if they don't need it

## 4. Frontend: pagination state and controls

- [x] 4.1 Replace the hardcoded `limit: 100` in `frontend/components/explorer/NodeTable.tsx` with component state `{ page: number, pageSize: number }`, defaulting to `{ page: 1, pageSize: 25 }`
- [x] 4.2 Compute `limit = pageSize` and `offset = (page - 1) * pageSize` and pass them into `useNodes`
- [x] 4.3 Add a `<Pagination>` element under the table rendering: prev button, "Page X of Y · M results", next button, and a page-size `<select>` with options [25, 50, 100]
- [x] 4.4 Disable prev on page 1; disable next when `offset + items_returned >= total`
- [x] 4.5 Reset `page` to 1 whenever `pageSize` changes, any filter in `props.filters` changes, or the active sort column/direction changes (used a render-time previous-state pattern, not `useEffect`, on lint guidance)
- [x] 4.6 Add unit tests for: prev/next clicks call the API with the right offset; page-size change refetches with offset 0; filter change resets to page 1

## 5. Frontend: viewport-bounded layout

- [x] 5.1 Restructure the explorer shell (in `frontend/components/explorer/Explorer.tsx` and/or `frontend/app/page.tsx`) to a single `100dvh` flex column: header region, main region, footer region
- [x] 5.2 The main region SHALL be `flex-1 min-h-0 overflow-y-auto` so the table scrolls inside it; verify the page-level `<html>`/`<body>` does not scroll when the table overflows (applied to the inner `node-table-body` div; the outer `main` is `flex-1 min-h-0 flex flex-col`)
- [x] 5.3 Added an RTL test asserting the body wrapper carries `overflow-y-auto`, `flex-1`, and `min-h-0` (jsdom doesn't compute layout, so a true scroll-position assertion is not meaningful here — pending manual + Playwright follow-up if needed)
- [x] 5.4 Stats strip + query bar fit: verified visually via running stack on :3000

## 6. Frontend: extended footer (disclaimer + sources + kbd hints)

- [x] 6.1 Extend `frontend/components/explorer/ExplorerFooter.tsx` with three regions: kbd hints (existing), data sources, research-only disclaimer
- [x] 6.2 Sources region renders Shodan / NVD / MaxMind GeoIP as `<a>` links (`shodan.io`, `nvd.nist.gov`, `maxmind.com`)
- [x] 6.3 Disclaimer text SHALL be exactly: "For security research and educational purposes only. Information is provided as-is; do not use for unauthorized access."
- [x] 6.4 Two-row layout: kbd hints + scan trigger on the top row; sources + disclaimer on the bottom row, stacking below the `sm` breakpoint via `flex-col sm:flex-row`
- [x] 6.5 Added tests in `explorer-layout.test.tsx` for sources (Shodan/NVD/MaxMind GeoIP) and disclaimer ("research")

## 7. Verification

- [x] 7.1 `pnpm typecheck && pnpm lint && pnpm test` pass in `frontend/` (163/163 ✓)
- [x] 7.2 `python -m pytest tests/test_web_api.py -v` passes (35/35 ✓)
- [ ] 7.3 Manual: open the dashboard at http://localhost:3000, scroll the table — page does not scroll, footer stays visible, prev/next/page-size all work (servers running; awaiting user verification)
- [x] 7.4 `curl -i ... /api/v1/nodes?limit=1` returns `x-total-count: 412`
