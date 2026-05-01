## Why

Hardcoded example/demo IP addresses currently look identical to real scanned nodes when they leak into the database (tests, screenshots, manual seeds). This creates two problems: stats and trends silently include junk data, and developers/reviewers cannot tell at a glance whether a row in the dashboard reflects real reconnaissance or a fixture. We need an explicit, stable way to mark these rows so they are visually obvious in the UI and excludable from filters and analytics, and the canonical IP set MUST come exclusively from the IANA-reserved documentation ranges (RFC 5737) so the flag never collides with a real public host.

## What Changes

- Maintain a canonical, code-defined list of example IPs drawn exclusively from RFC 5737 documentation ranges (`192.0.2.7`, `198.51.100.13`, `203.0.113.42`, `203.0.113.99`) in a single module (`src/example_ips.py`).
- Add an `is_example` boolean column to the `Node` model, defaulting to `false`, populated automatically when the scanner integration persists or updates a node whose IP matches the canonical list.
- Expose `is_example` through the node serializers so it reaches the API and the frontend.
- Add an `is_example` filter to `GET /api/v1/nodes` (default behavior: include them so existing callers do not break; opt-out via `is_example=false`).
- Render example rows in the dashboard with a dedicated pink/rose accent (badge + row tint), driven by a new `--color-example-*` token in `DESIGN.md` so it works in both dark and light themes.
- Backfill `is_example` for already-stored nodes via a small data migration / repository helper invoked once, and on every scanner write going forward.
- Add tests covering: detection helper, scanner-integration backfill, API filter, and frontend rendering.

## Capabilities

### New Capabilities
- `example-data-flag`: defines the canonical set of example IPs, the persisted `is_example` flag on `Node`, and the rules for setting it.

### Modified Capabilities
- `database-storage`: adds the `is_example` column to the `Node` schema and a one-shot backfill step.
- `web-api`: adds `is_example` to the node response payload and an `is_example` query filter on `GET /api/v1/nodes`.
- `node-list-filtering`: adds a filter scenario for including/excluding example nodes.
- `web-dashboard`: adds the pink/rose visual treatment for example nodes in list and detail views.

## Impact

- **Code**: new `src/example_ips.py`; `src/db/models.py` (column + index); `src/db/scanner_integration.py` (set flag on write); `src/db/repositories/node_repository.py` (filter + backfill helper); `src/web/routers/nodes.py` and node schemas (filter + serializer); frontend node-list and node-detail components; `DESIGN.md` tokens + regenerated `frontend/lib/design-tokens.ts` and `globals.css`.
- **Database**: additive, non-breaking schema migration (`is_example BOOLEAN NOT NULL DEFAULT 0`, indexed). SQLite and PostgreSQL both supported.
- **API**: backward compatible. Default response now includes a new field, and the new filter is opt-in.
- **Tests**: new unit tests for the detector, repo backfill, API filter, and a frontend rendering test for the pink styling.
- **No breaking changes** to scanner credit usage or scan flow.
