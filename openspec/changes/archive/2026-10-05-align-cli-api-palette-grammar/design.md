## Context

`/DESIGN.md` mandates a 1:1 mapping between palette entries, CLI flags, and REST endpoints (rule D10). The dashboard redesign enforced palette ↔ REST parity and deferred CLI parity; this change closes that half. Additionally, the REST API is intended to become the single capability surface so LLM agents can operate the platform via MCP (tools map 1:1 to endpoints); anything CLI-only is invisible to MCP consumers.

## Decisions

**1. Promote every CLI command to REST.** Driven by the MCP goal: `db-trends` → `GET /api/v1/trends`, `db-export` → `GET /api/v1/export` (JSON dump download), `db-import` → `POST /api/v1/import` (JSON body upload, API key + CSRF), `enrich-geo` → `POST /api/v1/enrich-geo` (background job, reusing `ScanJob` + `background.py` like the enrichment runner), `--check-credits` → `GET /api/v1/credits`. The CLI stays as a thin wrapper.

**2. `GET /api/v1/credits` reads local tracking only.** It returns the usage history recorded by `src/credit_tracker.py` (and today's remaining budget), without calling the Shodan API on each request — a dashboard polling the endpoint must never burn credits or add latency. Live account info stays in the CLI's `--check-credits`.

**3. CLI rename with deprecation window.** `db-stats` → `stats`; the old name remains as an alias that logs a deprecation warning, removed in the release after this lands. The CLI's extra stats fields are exposed via REST (`StatsOut` extended) rather than trimming the CLI — data is already computed, hiding it helps nobody.

**4. `node: open <ip>` and `GET /api/v1/nodes/by-ip/{ip}` are dropped.** The QueryBar already covers IP lookup via `GET /api/v1/nodes?ip=`; a dedicated endpoint would only save one click.

**5. Palette argument-input mode.** A command declaring `requiresArg` transitions the palette to an arg-input row (command name + input); Enter executes, Esc returns to the list. This unblocks `scan: status <job_id>` and `node: filter country <code>`, and is the generic mechanism for future arg-taking commands.

## Risks / Trade-offs

- [Bulk import over HTTP can be large] → `POST /api/v1/import` accepts the same dump shape as `db-import`; API key + CSRF required; size bounded by reverse-proxy limits (documented in docs).
- [`/api/v1/credits` can go stale vs the real Shodan balance] → documented as "locally tracked usage"; the CLI remains the tool for live account info.
