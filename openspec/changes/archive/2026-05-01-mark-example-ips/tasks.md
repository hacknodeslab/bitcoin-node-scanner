## 1. Canonical example IP module

- [x] 1.1 Create `src/example_ips.py` with `EXAMPLE_IPS = frozenset({"192.0.2.7", "198.51.100.13", "203.0.113.42", "203.0.113.99"})` (RFC 5737 documentation ranges only) and `is_example_ip(ip) -> bool` (handles `None`, empty, malformed inputs by returning `False`)
- [x] 1.2 Add `tests/test_example_ips.py` covering recognized IPs, unknown IPs, and invalid inputs

## 2. Database schema

- [x] 2.1 Add `is_example: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=expression.false(), index=True)` to `Node` in `src/db/models.py`
- [x] 2.2 In `src/db/connection.py` (or a small dedicated startup helper), detect the missing column on existing databases and issue `ALTER TABLE nodes ADD COLUMN is_example BOOLEAN NOT NULL DEFAULT 0` for SQLite and the equivalent `... DEFAULT FALSE` for PostgreSQL; idempotent (skip if column exists)
- [x] 2.3 Confirm `Base.metadata.create_all` produces the column on a fresh DB in both SQLite and PostgreSQL; add a regression test in `tests/test_db_models.py` (or extend an existing one) asserting the column and index exist

## 3. Scanner integration

- [x] 3.1 In `src/db/scanner_integration.py`, on every code path that creates or updates a `Node`, set `node.is_example = is_example_ip(node.ip)`
- [x] 3.2 Extend `tests/test_db_scanner_integration_extended.py` (or add a new test file) with cases: new example node gets `is_example=True`; new non-example node gets `is_example=False`; existing example node with stale `False` is corrected on upsert

## 4. Repository + CLI backfill

- [x] 4.1 Add `NodeRepository.backfill_example_flag()` in `src/db/repositories/node_repository.py` that runs (1) `UPDATE nodes SET is_example=TRUE WHERE ip IN (...)` and (2) `UPDATE nodes SET is_example=FALSE WHERE is_example=TRUE AND ip NOT IN (...)`. Returns counts for logging.
- [x] 4.2 Add CLI subcommand `db-mark-examples` to `src/db/cli.py` that calls `backfill_example_flag()` and prints the counts; document it in `CLAUDE.md` next to `enrich-geo` and `db-link-cves`
- [x] 4.3 Add `tests/test_db_cli.py` cases for the new subcommand covering: backfill flips correct rows; idempotent on second run; clears stale flag on rows whose IP is no longer canonical

## 5. API: filter and serializer

- [x] 5.1 Add `is_example: bool` to the node response schema in `src/web/schemas/` (or wherever node Pydantic models live) and ensure repository read paths populate it from `Node.is_example`
- [x] 5.2 Add `is_example: Optional[bool] = None` query parameter to `GET /api/v1/nodes` in `src/web/routers/nodes.py` and apply it to the SQLAlchemy query; reject non-boolean values with 422 (FastAPI handles this via type annotation)
- [x] 5.3 Extend `tests/test_web_api.py` with: list response includes `is_example` field; `?is_example=false` excludes example rows; `?is_example=true` returns only example rows; `?is_example=maybe` returns 422; combined `?risk_level=CRITICAL&is_example=false` works

## 6. Frontend: tokens and styling

- [x] 6.1 Add `color.example-bg`, `color.example-fg`, `color.example-border` to the `themes:` map in `DESIGN.md` for both `dark` and `light` (pink/rose tones; pick values that contrast against existing surface tokens)
- [x] 6.2 Run `pnpm tokens:gen` to regenerate `frontend/lib/design-tokens.ts` and the `:root` + `[data-theme="light"]` blocks in `frontend/app/globals.css`
- [x] 6.3 Add a Tailwind utility mapping (or update `tailwind.config`) so components can reference `bg-example`, `text-example`, `border-example` via the new CSS variables

## 7. Frontend: explorer + drawer rendering

- [x] 7.1 Update the node row component in `frontend/components/` (explorer table) to apply the example tokens and render an `EXAMPLE` badge when `node.is_example` is `true`
- [x] 7.2 Update the node detail drawer header (`NodeDetailDrawer` or equivalent) to show the same `EXAMPLE` badge when `node.is_example` is `true`
- [x] 7.3 Extend `frontend/components/__tests__/NodeDetailDrawer.test.tsx` (or add a new test) to verify the badge appears for `is_example: true` and is absent for `is_example: false`
- [x] 7.4 Add a frontend test for the explorer row asserting the row carries the example accent class/token when `is_example` is `true`

## 8. Frontend: hide-examples toggle

- [x] 8.1 Add a hide-examples toggle to the explorer controls (placement consistent with existing filters); wire it into the node-list query state
- [x] 8.2 When the toggle is on, send `is_example=false` to `GET /api/v1/nodes`; when off, omit the parameter
- [x] 8.3 Add a test for the toggle behavior (toggle on → fetch URL contains `is_example=false`; toggle off → URL omits it)

## 9. Documentation

- [x] 9.1 Update `CLAUDE.md` to mention `db-mark-examples` under the Database CLI section and to note the `is_example` field on `Node`
- [x] 9.2 Note in the `web-api` section of `CLAUDE.md` that `is_example` is now part of the node payload and accepted as a filter

## 10. Verification

- [x] 10.1 Run `python -m pytest tests/ -v` and confirm all backend tests pass (519 passing; 8 failures pre-existing on main, verified via `git stash`)
- [x] 10.2 Run `pnpm --filter frontend test` (or the project's equivalent) and confirm frontend tests pass (171/171 passing)
- [x] 10.3 Manually load the dashboard against a DB containing one of the example IPs and visually confirm the pink/rose accent renders correctly in both `dark` and `light` themes (verified in PRO and local after deploy of merge 13072c9)
- [x] 10.4 Run `openspec validate mark-example-ips` and confirm the change validates cleanly before archiving
