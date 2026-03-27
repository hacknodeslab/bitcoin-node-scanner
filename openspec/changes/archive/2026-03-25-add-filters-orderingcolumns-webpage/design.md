## Context

The dashboard table currently fetches from `GET /api/v1/nodes` with only `risk_level`, `limit`, and `offset` params. All ordering is done in the DB by `last_seen DESC` (hardcoded). The frontend has a single `<select>` for risk level. Columns: IP, Port, Version, Risk Level, Server Location, IP Registry, Last Seen.

The Node SQLAlchemy model already has all the fields that need sorting. No schema migrations needed.

## Goals / Non-Goals

**Goals:**
- Server-side sorting via `sort_by` and `sort_dir` query params on `GET /api/v1/nodes`
- Server-side filtering by `country` (maps to `country_name` / `country_code`)
- Clickable `<th>` headers in the frontend with asc/desc toggle indicator (▲/▼)
- Country filter dropdown populated from the distinct countries present in the DB
- Combined filtering: risk level + country can be active simultaneously

**Non-Goals:**
- Full-text search
- Client-side sorting (all ordering done server-side)
- Pagination UX redesign
- New API endpoints — extend existing `/api/v1/nodes` only

## Decisions

**D1 — Sort params as query strings, not headers**
`?sort_by=last_seen&sort_dir=desc` keeps the API REST-conventional and easily bookmarkable. Alternative (sort in request body) rejected — GET semantics.

**D2 — `sort_by` maps to a whitelist of column names**
Accept only a fixed set of sortable fields (`ip`, `port`, `version`, `risk_level`, `country_name`, `geo_country_name`, `last_seen`). Unknown values fall back to `last_seen`. Prevents SQL injection via ORM column mapping, not raw strings.

**D3 — Country filter matches `country_name` (Shodan) only**
Filtering by server location is the more useful case. `geo_country_name` can be added later. Matching is case-insensitive exact match (not prefix search) — countries come from a dropdown of known values, not free text.

**D4 — Country dropdown populated via a new `GET /api/v1/nodes/countries` endpoint**
Returns distinct non-null `country_name` values sorted alphabetically. Simpler than embedding them in `/stats`. Frontend fetches this once on page load.

**D5 — Sort indicator in `<th>` via Unicode arrows, no CSS library**
Keeps the single-file dashboard self-contained. Active column gets ▲ or ▼ appended; inactive columns get a dim `⇅` hint.

## Risks / Trade-offs

- [Risk] Large result sets with sorting on non-indexed columns (`version`, `geo_country_name`) may be slow → Acceptable for current scale (~10k nodes max); add index if profiling shows it
- [Risk] Country dropdown grows large for diverse datasets → Limit to top 100 distinct countries
- [Trade-off] Server-side sort means every column click is a new network request → Acceptable; results are already paginated so client-side sort would only sort the current page anyway

## Migration Plan

No DB migration needed. Deploy is a drop-in replacement of `nodes.py` and `index.html`. Rollback: revert both files.

## Open Questions

None — scope is well-defined.
