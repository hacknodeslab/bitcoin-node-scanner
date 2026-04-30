## Why

`/DESIGN.md` mandates a 1:1 mapping between palette entries, CLI flags, and REST endpoints. The dashboard redesign (`redesign-dashboard-design-system`, design.md D10) honoured this in spirit by enforcing palette ↔ REST parity now and explicitly deferring CLI parity. This change closes the deferred half.

Concrete drift identified during the redesign (2026-04-25):

- `db-stats` (CLI) returns more fields than `GET /api/v1/stats`. The CLI name is also inconsistent with the REST surface (`stats`, not `db-stats`).
- `db-trends`, `db-export`, `db-import`, `enrich-geo`, and `--check-credits` exist as CLI commands but have no REST equivalent.
- `node: open <ip>` in the palette had to fall back to a list-and-scan helper because there is no `GET /api/v1/nodes/by-ip/{ip}` endpoint.
- Several palette commands that need an argument prompt (`scan: status <job_id>`, `node: filter country <code>`) ship as deferred placeholders in `lib/commands.ts` until both the REST surface and an argument-input mode in the palette UI exist.

## What Changes

- **REST surface additions**:
  - `GET /api/v1/nodes/by-ip/{ip}` — direct lookup so `node: open <ip>` from the palette doesn't need to scan the list.
  - Decide whether `db-trends`, `db-export`, `db-import`, `enrich-geo` should be promoted to REST endpoints or remain CLI-only with documented rationale.
  - `GET /api/v1/credits` (or similar) for `--check-credits` parity, if we keep it user-facing.
- **CLI renames**: `db-stats` → `stats`, with the old name kept as a deprecated alias for one release. Align field set with the REST `StatsOut` (or expose the CLI's extra fields via REST).
- **Palette additions**: re-enable `scan: status <job_id>`, `node: filter country <code>`, `node: open <ip>` once the REST endpoints exist; introduce an argument-input mode in the `CommandPalette` primitive (input row stays after the command name, focus shifts to the arg input).
- **Documentation**: update `/DESIGN.md` to reflect the rule reformulation captured in `redesign-dashboard-design-system` design.md D10.

## Capabilities

### Modified Capabilities

- `web-dashboard`: REST surface grows the new endpoints listed above; the palette ↔ REST registry in `frontend/lib/commands.ts` gains the previously deferred entries.

### New Capabilities

- `cli-stats-parity`: CLI `stats` (renamed from `db-stats`) exposes the same fields as `GET /api/v1/stats`, plus optional CLI-only flags documented as such.

## Impact

- Endpoints added to `src/web/routers/nodes.py` (and possibly `stats.py`).
- CLI renames in `src/db/cli.py` with deprecation aliases for one release.
- Palette specs in `frontend/lib/commands.ts` move from "deferred" to "shipped".
- New tests for each REST endpoint and the CLI alias compatibility.
- Documentation: `/DESIGN.md`, `README.md`, `CLAUDE.md` reflect the closed parity.

## Out of Scope

- L402 payment flow — see `l402-payment-flow`.
- Visual changes to existing palette entries.
