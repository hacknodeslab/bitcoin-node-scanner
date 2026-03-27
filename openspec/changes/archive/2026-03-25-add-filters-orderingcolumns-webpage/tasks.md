## 1. API — Sorting & Filtering

- [x] 1.1 Add `sort_by`, `sort_dir`, and `country` query params to `list_nodes` in `src/web/routers/nodes.py` with a whitelist mapping of valid `sort_by` values to SQLAlchemy `Node` columns
- [x] 1.2 Apply `order_by` dynamically based on `sort_by`/`sort_dir`; fall back to `last_seen DESC` for unknown values
- [x] 1.3 Apply case-insensitive `country_name` filter when `country` param is present (combine with existing `risk_level` filter)

## 2. API — Countries Endpoint

- [x] 2.1 Add `GET /api/v1/nodes/countries` endpoint in `src/web/routers/nodes.py` returning a sorted list of distinct non-null `country_name` values (limit 100), protected by `require_api_key`

## 3. Frontend — Sortable Headers

- [x] 3.1 Add JS state variables `sortBy` (default `last_seen`) and `sortDir` (default `desc`) to `index.html`
- [x] 3.2 Convert all `<th>` elements to clickable elements that update `sortBy`/`sortDir` and call `fetchNodes()`
- [x] 3.3 Render sort indicators: ▼/▲ on the active column, dim ⇅ on inactive columns; update on each fetch

## 4. Frontend — Country Filter

- [x] 4.1 Add a country `<select>` dropdown to the toolbar in `index.html` with a blank "All Countries" default option
- [x] 4.2 Add `fetchCountries()` function that calls `GET /api/v1/nodes/countries` and populates the dropdown on page load
- [x] 4.3 Wire the country dropdown `change` event to update a `currentCountry` state variable, reset to page 0, and call `fetchNodes()`
- [x] 4.4 Pass `country` param to the API call in `fetchNodes()` when `currentCountry` is set

## 5. Tests

- [x] 5.1 Add tests to `tests/test_web_api.py` covering: sort by `ip` asc, sort by `last_seen` desc, invalid `sort_by` falls back gracefully, `country` filter returns matching nodes only, `GET /api/v1/nodes/countries` returns sorted list and requires API key
