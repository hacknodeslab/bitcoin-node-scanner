## 1. Frontend setup

- [ ] 1.1 Add a `severity` → CVE-pill mapping helper for `risk_level` (CRITICAL/HIGH/MEDIUM/LOW) at the top of `frontend/components/explorer/NodeDetailDrawer.tsx`. Re-use the existing `severityToCveSeverity` helper introduced in the prior change if it covers the cases.
- [ ] 1.2 Add a `tagsToPillProps(tags: string[])` helper that maps reserved tags `tor` and `bitcoin` to their dedicated colour tones and falls back to a generic neutral tone for unknown tags. Co-locate with the drawer for now; promote to `frontend/lib/` if reused.

## 2. Drawer header (lines 1, 2, 3 + pill row)

- [ ] 2.1 Update the meta row (line 1) to render `seen <last_seen>` and, when `node.first_seen` is non-null, append ` · since <first_seen>` before the ASN segment.
- [ ] 2.2 In the IP/port line (line 2), insert an inline pill row immediately after the `EXAMPLE` pill that renders, in order: `DEV` (when `is_dev_version`), the `risk_level` pill, and one pill per `node.tags` entry. Apply `flex-wrap` so overflow drops to a new line.
- [ ] 2.3 Replace the current subtitle (line 3) with the composed string per spec: `version` · locality (`city, subdivision, country_name` joined and pruned of nulls) · MaxMind suffix `(MM: <geo_country_name>)` only when `geo_country_code !== country_code`. Drop separators around omitted segments.
- [ ] 2.4 Remove the legacy `node.user_agent` mention from the subtitle (it is now subsumed by `version` and is null for ~99% of nodes).

## 3. Banner card

- [ ] 3.1 Insert a new `Card` with `data-testid="card-banner"` and `CardLabel` `banner` between the open-ports card and the vulnerabilities card in the existing `Tabs` body (still under the `ports` tab content area is wrong — the banner card belongs in the top-level drawer body, not inside a tab; place it above the `Tabs` block so it is always visible).
- [ ] 3.2 Render `node.banner` inside `<pre className="font-mono text-body-sm whitespace-pre-wrap max-h-[180px] overflow-y-auto px-[12px] py-[8px]">`. Ensure React's default escaping is left in place (no `dangerouslySetInnerHTML`).
- [ ] 3.3 Skip the banner card entirely when `node.banner` is null or empty (do not render the card frame).

## 4. Host metadata card (rename + fill)

- [ ] 4.1 Rename the third tab trigger from `refs` to `host` in `TabsTrigger value="refs"` block. The `value` attribute can stay `refs` to avoid touching every test, but the visible label SHALL be `host`. (Better: change both `value` and label to `host` and update tests.)
- [ ] 4.2 Replace the placeholder `· cross-references arrive in a future change` row in the third-tab card with a row generator that emits, in order, the rows defined in the spec: ASN+name, ISP, ORG, HOSTNAME, GEO (Shodan), GEO (MaxMind), LAT/LON. Skip rows whose source field is null/empty.
- [ ] 4.3 When the row generator produces zero rows, render exactly one `meta`-typography `dim` line `· no host metadata available`.
- [ ] 4.4 Update the `CardLabel` from `cross-references` to `host metadata`. Keep the `data-testid="card-refs"` for backward compatibility OR switch to `card-host` and update tests in 5.x.

## 5. Test fixtures + assertions

- [ ] 5.1 Update `frontend/components/__tests__/NodeDetailDrawer.test.tsx` `NODE` fixture to include `version: "Satoshi:0.21.0"`, `tags: ["bitcoin"]`, `banner: "Bitcoin:\n  User-Agent: /Satoshi:0.21.0/"`, `risk_level: "MEDIUM"`, etc. (most are already present after the previous change).
- [ ] 5.2 Add a test: when `is_dev_version=true`, the header renders a `DEV` pill (locate by text or `data-testid`).
- [ ] 5.3 Add a test: when `tags=["bitcoin","tor"]`, the header renders two pills (one per tag).
- [ ] 5.4 Add a test: subtitle includes `version` and locality string for a fully-described node, and excludes the MaxMind suffix when `country_code === geo_country_code`.
- [ ] 5.5 Add a test: subtitle appends `· (MM: France)` when Shodan says `DE` and MaxMind says `FR`.
- [ ] 5.6 Add a test: a node with `banner` set renders a `card-banner` with the banner text inside a `<pre>`; a node with `banner=null` renders no `card-banner`.
- [ ] 5.7 Add a test: the host metadata card renders exactly the rows for which source data is non-null; rename existing `card-refs` lookups to `card-host` if the test-id changed in 4.4.
- [ ] 5.8 Add a test: an empty-host-metadata node (all relevant fields null) renders the `· no host metadata available` line.
- [ ] 5.9 Add a test: the third tab trigger has the visible label `host`.

## 6. Verify

- [ ] 6.1 Run `pnpm typecheck` — must pass.
- [ ] 6.2 Run `pnpm test --run` — full vitest suite must pass.
- [ ] 6.3 Run the dev server (`pnpm dev`) against the live FastAPI backend, open the drawer for a real `Satoshi:29.x` node and visually verify: version pill, risk_level pill, banner card with multi-line content, host card with ASN row, no MaxMind suffix when countries agree.
- [ ] 6.4 Open the drawer for `192.0.2.7` (one of the seed `is_example` nodes) and verify it shows ISP/ORG/HOSTNAME rows in the host card, plus tags pills.
- [ ] 6.5 Manually shrink the viewport to ~720px and confirm the header pill row wraps cleanly without truncation.
