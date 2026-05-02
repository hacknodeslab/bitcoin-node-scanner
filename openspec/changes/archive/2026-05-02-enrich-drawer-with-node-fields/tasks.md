## 1. Frontend setup

- [x] 1.1 Add a `severity` → CVE-pill mapping helper for `risk_level` (CRITICAL/HIGH/MEDIUM/LOW) at the top of `frontend/components/explorer/NodeDetailDrawer.tsx`. Re-use the existing `severityToCveSeverity` helper introduced in the prior change if it covers the cases.
- [x] 1.2 Add a `tagsToPillProps(tags: string[])` helper that maps reserved tags `tor` and `bitcoin` to their dedicated colour tones and falls back to a generic neutral tone for unknown tags. Co-locate with the drawer for now; promote to `frontend/lib/` if reused.

## 2. Drawer header (lines 1, 2, 3 + pill row)

- [x] 2.1 Update the meta row (line 1) to render `seen <last_seen>` and, when `node.first_seen` is non-null, append ` · since <first_seen>` before the ASN segment.
- [x] 2.2 In the IP/port line (line 2), insert an inline pill row immediately after the `EXAMPLE` pill that renders, in order: `DEV` (when `is_dev_version`), the `risk_level` pill, and one pill per `node.tags` entry. Apply `flex-wrap` so overflow drops to a new line.
- [x] 2.3 Replace the current subtitle (line 3) with the composed string per spec: `version` · locality (`city, subdivision, country_name` joined and pruned of nulls) · MaxMind suffix `(MM: <geo_country_name>)` only when `geo_country_code !== country_code`. Drop separators around omitted segments.
- [x] 2.4 Remove the legacy `node.user_agent` mention from the subtitle (it is now subsumed by `version` and is null for ~99% of nodes).

## 3. Banner card

- [x] 3.1 Place the `Card` with `data-testid="card-banner"` and `CardLabel` `banner` above the `Tabs` block so it is always visible. (Spec text updated to match: "above the tabs row".)
- [x] 3.2 Render `node.banner` inside `<pre className="font-mono text-body-sm whitespace-pre-wrap max-h-[180px] overflow-y-auto px-[12px] py-[8px]">`. React's default escaping is left in place (no `dangerouslySetInnerHTML`).
- [x] 3.3 Skip the banner card entirely when `node.banner` is null or empty (do not render the card frame).

## 4. Host metadata card (rename + fill)

- [x] 4.1 Rename the third tab trigger from `refs` to `host`. Both `value` and visible label switched to `host`; `data-testid="tab-count-host"` added.
- [x] 4.2 Replace the placeholder `· cross-references arrive in a future change` row with `buildHostMetadataRows(node)` that emits the rows in spec order (ASN+name, ISP, ORG, HOSTNAME, GEO Shodan, GEO MaxMind, LAT/LON), skipping null fields.
- [x] 4.3 When the row generator produces zero rows, render the single `· no host metadata available` line in `meta`-typography `dim` colour.
- [x] 4.4 Update the `CardLabel` from `cross-references` to `host metadata`. Test-id changed from `card-refs` to `card-host`; per-row test-ids `host-row-<key>` added.

## 5. Test fixtures + assertions

- [x] 5.1 `NODE` fixture in `frontend/components/__tests__/NodeDetailDrawer.test.tsx` updated with `banner: null`, `latitude: null`, `longitude: null`. `NodeTable.test.tsx` and `explorer-layout.test.tsx` fixtures likewise extended.
- [x] 5.2 New test: `is_dev_version=true` renders a `DEV` pill; absence asserted when false.
- [x] 5.3 New test: `tags=["bitcoin","tor"]` renders pills with `data-pill-kind="BITCOIN"` and `data-pill-kind="TOR"`. Plus a separate test for unknown tags rendering as `data-pill-kind="TAG"`.
- [x] 5.4 New test: subtitle includes `version` + locality (`Reston, Virginia, United States`) when countries match (no MaxMind suffix).
- [x] 5.5 New test: subtitle appends `(MM: France)` when Shodan says `DE` and MaxMind says `FR`.
- [x] 5.6 New test: banner present → `card-banner` and `<pre>` render the multi-line text; banner null → no `card-banner`.
- [x] 5.7 New test: host metadata card renders only the rows whose source field is non-null. Uses `initialTab="host"` to force the tab visible (Radix unmounts inactive tab content in jsdom).
- [x] 5.8 New test: empty-host-metadata node renders `· no host metadata available`.
- [x] 5.9 New test: third tab is labelled `host` (asserted via the parent of `tab-count-host`).
- [x] 5.10 (extra) New test: `RISK` pill renders the severity uppercased (`CRITICAL`).
- [x] 5.11 (extra) New tests for `first_seen` segment presence/absence.

## 6. Verify

- [x] 6.1 `pnpm typecheck` — passing.
- [x] 6.2 `pnpm test --run` — 186/186 tests passing. Backend `pytest tests/test_web_api.py` also re-run (47/47).
- [x] 6.3 Manual: run the dev server (`pnpm dev`) against the live FastAPI backend, open the drawer for a real `Satoshi:29.x` node and visually verify: version pill, risk_level pill, banner card with multi-line content, host card with ASN row, no MaxMind suffix when countries agree.
- [x] 6.4 Manual: open the drawer for `192.0.2.7` (one of the seed `is_example` nodes) and verify it shows ISP/ORG/HOSTNAME rows in the host card, plus tags pills.
- [x] 6.5 Manual: shrink the viewport to ~720px and confirm the header pill row wraps cleanly without truncation.

## 7. Backend addition (discovered during apply)

- [x] 7.1 Add `banner: Optional[str]`, `latitude: Optional[float]`, `longitude: Optional[float]` to `NodeOut` Pydantic model in `src/web/routers/nodes.py` (proposal originally claimed "no backend change"; corrected here).
- [x] 7.2 Update `_node_out_kwargs` to populate the three new fields from the SQLAlchemy `Node` instance.
- [x] 7.3 Mirror the new fields in the TypeScript `NodeOut` interface (`frontend/lib/api/types.ts`).
