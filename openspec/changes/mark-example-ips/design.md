## Context

Example/demo IPs are used in tests, fixtures, and screenshots. The canonical set is drawn exclusively from IANA documentation ranges reserved by RFC 5737 — `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3) — so the flag never collides with a real public host. (An earlier iteration of this change used `1.2.3.4`, `5.6.7.8`, `9.10.11.12`, `1.3.3.7`; those are routable Cloudflare/APNIC/etc. addresses and were replaced before merge.) These IPs can land in `bitcoin_scanner.db` (manual seeds, dev runs against fixtures, copy-pasted screenshots) and become indistinguishable from real Shodan results, polluting `/api/v1/stats`, trends, and the dashboard. The scanner pipeline is the only writer of `Node` rows in production, so a flag set at write-time plus a one-time backfill is sufficient — no continuous reconciliation is needed.

The frontend already has a token-based theming system (`DESIGN.md` → `pnpm tokens:gen` → CSS variables consumed by Tailwind), so a new pink/rose accent fits the existing pattern. Both `dark` and `light` themes must define the new token.

## Goals / Non-Goals

**Goals:**
- Single source of truth for example IPs (one Python module, one matching frontend constant if needed).
- Persisted `is_example` boolean on `Node`, set automatically on every write and backfilled for existing rows.
- API surface (`is_example` in payload + opt-in filter) and dashboard treatment (pink/rose badge + row tint) that work in both themes.
- Backward-compatible API and DB migration (additive column, default `false`).

**Non-Goals:**
- Configurable example-IP lists per deployment (the four IPs are hardcoded; can be changed by editing `src/example_ips.py`).
- Excluding example nodes from `/api/v1/stats` aggregations in this change — that can come later behind the same flag once the column is in place.
- Changing scanner behavior or Shodan queries; example IPs would never be returned by Shodan in practice, so this is purely about data hygiene.
- Auditing existing tests/fixtures to deduplicate test IPs.

## Decisions

### Decision 1: Persist `is_example` as a column, not derive it on read

**Choice:** Add `is_example BOOLEAN NOT NULL DEFAULT FALSE` to the `nodes` table, indexed.

**Why:**
- Filtering and aggregation queries stay simple and indexable (`WHERE is_example = false`).
- The detection rule (membership in a small hardcoded set) is cheap, but applying it on every read is awkward when filtering — pushing it into SQL would couple repo queries to a Python list.
- A persisted flag also lets future code (scoring, exports) cleanly carry the bit without re-checking.

**Alternative considered:** Compute on the fly in repositories or serializers. Rejected because the API filter (`?is_example=false`) would either need raw SQL with a hardcoded `IN (...)` clause or post-filtering in Python (broken pagination).

### Decision 2: Set the flag inside `db/scanner_integration.py`, not the scanner itself

**Choice:** The scanner stays oblivious. `scanner_integration.persist_node` (or equivalent upsert path) calls `is_example_ip(ip)` from `src/example_ips.py` and writes the result.

**Why:**
- `scanner.py` deals in Shodan results, not DB shape.
- Keeps the rule applied uniformly regardless of which scanner variant (`BitcoinNodeScanner`, `OptimizedBitcoinScanner`) produced the row.
- Easy to unit-test the integration layer in isolation.

### Decision 3: Backfill via a repository helper invoked once

**Choice:** Add `NodeRepository.backfill_example_flag()` which runs `UPDATE nodes SET is_example = TRUE WHERE ip IN (...)`. Invoke it from the existing CLI (`src/db/cli.py`) under a new subcommand `db-mark-examples`, and also call it once at API startup in dev (idempotent).

**Why:**
- The set is tiny and well-known, so a full migration script is overkill.
- A repo method composes naturally with the existing repository pattern and is easy to test.
- CLI invocation matches existing operational patterns (`enrich-geo`, `db-link-cves`).

**Alternative considered:** Alembic-style migration. Rejected because the project does not currently use a migration framework — schema evolution happens via `Base.metadata.create_all` plus targeted CLI fixers, and we should match that.

### Decision 4: API filter defaults to "include examples"

**Choice:** `GET /api/v1/nodes` continues to return example nodes by default. The new `is_example` query parameter is opt-in (`?is_example=false` to hide, `?is_example=true` to show only examples).

**Why:**
- Backward compatibility for any existing dashboard or external consumer.
- The dashboard can pass `is_example=false` explicitly when it wants a "real-data-only" view.

**Risk:** Stats aggregations still include examples until that follow-up is done. Mitigation: documented as out of scope; the row count in the dashboard will visibly mark them in pink so the inflation is obvious.

### Decision 5: Pink/rose styling via a new theme token

**Choice:** Add `--color-example-bg`, `--color-example-fg`, `--color-example-border` (or similar trio) to `DESIGN.md`'s `themes:` map for both `dark` and `light`. Regenerate `frontend/lib/design-tokens.ts` and `globals.css` via `pnpm tokens:gen`. Apply via a Tailwind class composition (`bg-example/10 text-example border-example/40` or whatever maps to the tokens) on the relevant row container and a `<Badge variant="example">EXAMPLE</Badge>`.

**Why:**
- Follows the documented theming pipeline; avoids hardcoded hex colors in components.
- Both themes get treated; no FOUC because the pre-hydration script already swaps `data-theme`.

### Decision 6: No frontend duplication of the IP list

**Choice:** The list of example IPs lives only in the backend (`src/example_ips.py`). The frontend reacts to `node.is_example` from the API, never to the IP itself.

**Why:** Single source of truth. If the list changes, only one file and one backfill run are needed.

## Risks / Trade-offs

- **Stats inflation persists** → Documented non-goal; follow-up issue can add `exclude_examples=true` to `/api/v1/stats`.
- **Backfill not run in some environment** → CLI command + idempotent startup call mitigates. Worst case the row simply lacks the badge until someone runs `db-mark-examples`.
- **Hardcoded list drift** → Mitigated by centralization in `src/example_ips.py` and a unit test asserting the canonical four IPs are present.
- **SQLite vs PostgreSQL boolean semantics** → SQLAlchemy's `Boolean` handles both; `connection.py` already deals with SQLite quirks (FK pragmas). The `IN (...)` query and `WHERE is_example = false` work identically.
- **Adding a column to a populated SQLite DB** → `ALTER TABLE ... ADD COLUMN ... DEFAULT FALSE NOT NULL` is supported; SQLAlchemy's `create_all` is a no-op for existing tables, so we need the CLI subcommand (or a startup hook) to issue the `ALTER TABLE` for users with an existing DB. Document in CLAUDE.md.

## Migration Plan

1. Land code with the new column declared in `models.py`. Fresh DBs get it via `create_all`.
2. Existing DBs: a startup hook in `db/connection.py` (or the new `db-mark-examples` CLI) detects the missing column via `PRAGMA table_info` / `information_schema` and issues `ALTER TABLE`.
3. Run `db-mark-examples` (or trigger the idempotent startup call) to backfill the flag.
4. Frontend deploys after backend so it never references a field that the API has not yet shipped.
5. Rollback: drop the column (or just leave it — no consumers will break since the field is additive).
