## 1. REST surface

- [ ] 1.1 Add `GET /api/v1/nodes/by-ip/{ip}` returning the same shape as `/nodes/{id}/geo`'s parent (or a dedicated `NodeOut`); 404 when not found.
- [ ] 1.2 Decide promotion vs documented CLI-only status for `db-trends`, `db-export`, `db-import`, `enrich-geo`, `--check-credits`. Capture decision in this change's design.md.
- [ ] 1.3 If promoted, add the corresponding endpoints with tests covering happy path + auth.

## 2. CLI alignment

- [ ] 2.1 Rename `db-stats` → `stats`; keep `db-stats` as a deprecated alias logging a warning, slated for removal in the release after this lands.
- [ ] 2.2 Reconcile the CLI `stats` field set with the REST `StatsOut` — either trim the CLI to the REST shape or expose the extras via REST too. Prefer the latter.

## 3. Palette re-enablement

- [ ] 3.1 Add an argument-input mode to `CommandPalette`: when the focused command declares `requiresArg`, run executes a transition that renders an arg input bound to the command's resolver.
- [ ] 3.2 Re-introduce `scan: status <job_id>`, `node: filter country <code>`, `node: open <ip>` in `frontend/lib/commands.ts` with their REST endpoints, no longer in the deferred list.

## 4. Documentation

- [ ] 4.1 Update `/DESIGN.md` to reflect D10's rule reformulation (mandatory palette ↔ REST; CLI parity tracked here, not in the design rule).
- [ ] 4.2 Update `README.md` and `CLAUDE.md` API reference tables.

## 5. Verification

- [ ] 5.1 Backend: `pytest` covers every new endpoint.
- [ ] 5.2 Frontend: the palette ↔ REST parity test (`commands.test.ts`) stays green with the new entries.
- [ ] 5.3 `openspec validate align-cli-api-palette-grammar` passes.
