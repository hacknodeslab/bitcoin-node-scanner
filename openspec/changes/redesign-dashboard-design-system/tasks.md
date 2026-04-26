## 1. Resolve open questions before code lands

- [x] 1.1 shadcn anatomy decided per D4. **Keep (Radix anatomy + token-mapped overrides):** `Dialog`, `Popover`, `Tabs`, `Tooltip`, `ScrollArea`. **Fork (owned in `frontend/components/ui/`):** `Pill`, `Button`, `Card`, `Input`, `StatTile`, `TableRow`, `CommandPalette`, `Drawer`, `QueryBar`. Frozen 2026-04-25.
- [x] 1.2 Production CSRF posture: **`samesite=lax` uniformly across all environments** (no env-var bifurcation). Captured in D8.
- [x] 1.3 Token codegen tooling: **`yaml` (or `js-yaml`) as a dev dependency**, not hand-rolled — the front matter already uses `"{colors.alert-bg}"` references that need real parsing. Captured in Open Question 2 resolution.
- [x] 1.4 L402 endpoint shape: **adopt the standard 402 challenge convention** (`WWW-Authenticate: L402 macaroon=..., invoice=...` on the protected resource itself), not `POST /api/v1/l402/invoice`. Ship one example protected endpoint (`GET /api/v1/l402/example`) returning 402 with placeholder challenge values. Captured in D9.
- [x] 1.5 V0 palette command set frozen in `design.md` D10. Rule reformulated: every non-`NAV` palette command must have a REST endpoint; CLI parity is debt tracked in the follow-up `align-cli-api-palette-grammar`. Frozen 2026-04-25.

## 2. Backend preparation

- [x] 2.1 Add `FRONTEND_ORIGIN` env var (default `http://localhost:3000` for dev) and document it in `env.example` and `CLAUDE.md`
- [x] 2.2 Add CORS middleware to `src/web/main.py` allowing `FRONTEND_ORIGIN` (with credentials) for `/api/v1/*` and the CSRF token endpoint
- [x] 2.3 Switch `src/web/routers/csrf.py` cookie to `samesite="lax"` uniformly (no env-var bifurcation); add a regression test that the double-submit check still rejects requests where the header does not match the cookie
- [x] 2.4 Add an L402 challenge helper in `src/web/l402.py` that emits `402 Payment Required` with header `WWW-Authenticate: L402 macaroon="<placeholder>", invoice="<placeholder>"` and body `{"error": "l402_pending"}`; expose one example protected endpoint `GET /api/v1/l402/example` exercising the helper; cover with tests asserting status 402, the `WWW-Authenticate` header value, and the body shape
- [x] 2.5 Add a `GET /` redirect to `FRONTEND_ORIGIN` (302) and a deprecation comment with a calendar reminder for removal in 30 days. Active when `index.html` is absent (so legacy dashboard keeps working until cutover task 11.1).

## 3. Bootstrap `frontend/` Next.js project

- [x] 3.1 Create `frontend/` directory with `package.json` (Next.js 16.2.4, React 19.2.5, TypeScript 6.0.3 strict, pnpm 10), `tsconfig.json`, `next.config.ts`, `.gitignore`. Tailwind pinned to 3.4.19 per architectural decision (latest stable on everything else).
- [x] 3.2 Add `tailwind.config.ts`, `postcss.config.js`, and `frontend/app/globals.css` with `@tailwind base/components/utilities` directives plus codegen markers
- [x] 3.3 Add `frontend/app/layout.tsx` that sets `<html>`/`<body>` with `bg`/`text` token classes and applies the JetBrains Mono `next/font/google` font to `<html>`
- [x] 3.4 Wrote `components.json` and `lib/utils.ts` manually instead of running `pnpm dlx shadcn@latest init`, to avoid the CLI overwriting `tailwind.config.ts` / `globals.css`. Files match what init would generate (Default style, Neutral baseColor, cssVariables=false, RSC=true, TSX=true).
- [x] 3.5 Scripts in place: `dev`, `build`, `start`, `lint` (eslint .), `typecheck` (tsc --noEmit), `test` (no-op placeholder), `format` (prettier), `tokens:gen`, `tokens:check`. Note: `next lint` deprecated in Next 16; use `eslint .` directly.
- [x] 3.6 CI workflow `.github/workflows/ci.yml` adds a `frontend` job (Node 20, pnpm 10) running install → tokens:check → lint → typecheck → build

## 4. Tokens, fonts, and lint guardrails

- [x] 4.1 `frontend/scripts/generate-design-tokens.ts` parses `/DESIGN.md`'s YAML front matter (resolving `{...}` references), and emits `frontend/lib/design-tokens.ts` with typed constants for colors / fontFamily / fontSize / spacing / borderRadius / components
- [x] 4.2 `tailwind.config.ts` imports token sub-objects from `frontend/lib/design-tokens.ts` and replaces (not extends) Tailwind defaults so utilities outside our token set fail to compile. `borderRadius` resolves to `{ none: '0px' }` only.
- [x] 4.3 The same codegen script patches a `:root` block (delimited by `BEGIN/END GENERATED TOKENS` markers) in `frontend/app/globals.css` with CSS custom properties for colors, spacing, rounded, font sizes/weights/lineheights/letterspacings
- [x] 4.4 `pnpm tokens:check` re-runs the codegen and exits non-zero if the committed `design-tokens.ts` or `globals.css` differs. Wired into the `frontend` CI job.
- [x] 4.5 `frontend/app/layout.tsx` loads JetBrains Mono via `next/font/google` (weights 400/500/600, `display: 'swap'`) with monospace fallback chain `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`
- [x] 4.6 Custom ESLint plugin at `frontend/eslint-rules/index.cjs` exposes: `no-banned-classnames` (rounded/shadow/blur/backdrop/gradient), `no-banned-imports` (icon libs + non-mono font sources), `only-jetbrains-mono-font` (next/font/google), `no-inline-color`. Wired in `eslint.config.mjs`.
- [x] 4.7 `design-system/primary-allowlist` rule caps `text-primary` / `bg-primary` / `border-primary` to files matching `/components/brand/`, `/components/ui/Button.tsx`, `/components/ui/Tabs.tsx`
- [ ] 4.8 Add a Playwright/visual-regression test that fails when 4+ `primary`-coloured elements render simultaneously on any view. **Deferred to M5** — meaningful only against real rendered views (explorer/palette/drawer); ESLint `primary-allowlist` rule already caps decorative orange at static-analysis time.

## 5. Owned primitives in `frontend/components/ui/`

- [x] 5.1 `Pill.tsx` exports a `PillKind` discriminated union with EXPOSED/STALE/TOR/CVE(severity)/OK; `toneFor()` resolves each variant to alert/warn/ok colour pair; `padding: 2px 7px` per token
- [x] 5.2 `Button.tsx` with `secondary` (default) and `l402` variants. l402 prefixes the bolt glyph and uses `bg-l402-bg`, `text-primary`, `border-primary`. Bypasses `cn()` because `tailwind-merge` groups `text-meta` (size) and `text-primary` (color) as one utility.
- [x] 5.3 `Input.tsx`, `Card.tsx` (with `CardLabel` and `CardRow` subparts), and `StatTile.tsx` with `DeltaDirection` enum encoding the "rising EXPOSED is bad" semantic
- [x] 5.4 `Glyph.tsx` exports `GLYPHS` map (`chevron`, `caret`, `dot`, `bolt`, `search`, `cross`, `warn`, `sep`, `cmd` → `›`, `⌄`, `●`, `⚡`, `⌕`, `✗`, `⚠`, `·`, `⌘`); `GlyphName` is `keyof typeof GLYPHS`
- [x] 5.5 `TableRow.tsx` exports both `TableRow` (9px/14px padding, optional `selected` 2px primary left border) and `TableExpandedRow` (state-coloured 2px left border, `surface` bg, 32px left findings padding)
- [x] 5.6 `QueryBar.tsx` exports `parseQuery(input)` and renders parsed tokens with the controlled colour map (key→muted, eq→dim, value→text/ok/alert via ALERT_RULES/OK_RULES match)
- [x] 5.7 `Tabs.tsx` is a Radix-anatomy wrapper (`Tabs` / `TabsList` / `TabsTrigger` / `TabsContent`) with `meta` typography and `data-[state=active]:border-b data-[state=active]:border-primary` for the active underline
- [x] 5.8 `Drawer.tsx` (Radix Dialog with sliver + main panel, focus trap and Esc-to-close from Dialog) and `CommandPalette.tsx` (⌘K listener, flat alpha backdrop via Tailwind arbitrary value `bg-[rgba(0,0,0,0.5)]`, grouped commands, focused-item left border, single-line items, ↑↓/↵/Esc nav)
- [x] 5.9 Vitest + jsdom + RTL setup. Tests at `components/__tests__/ui.test.tsx` (33 cases): smoke pass over all primitives asserts no forbidden Tailwind utilities or inline shadow/blur/non-zero-radius styles; per-component contract tests (Pill discriminated tones, Button l402 vs secondary, Glyph allow-list, QueryBar parsing/colouring, StatTile delta direction, TableRow selection). Storybook intentionally skipped — heavier than the test surface needs.

## 6. shadcn keep-list overrides

- [x] 6.1 Manually wrote thin Radix wrappers in `components/ui/` for `Dialog`, `Popover`, `Tabs`, `Tooltip`, `ScrollArea` instead of running `pnpm dlx shadcn@latest add`. The CLI would have re-keyed shadcn's expected token names (`--background`, `--foreground`, etc.) which differ from ours; manual wrappers are ~50 LoC each and use our tokens directly via Tailwind classes. Radix runtime deps are listed in `package.json`.
- [x] 6.2 Each Radix wrapper composes only token-derived utilities — no `rounded-*`, no `shadow-*`, no gradients, no decorative greys. Dialog overlay is the documented exception (`bg-[rgba(0,0,0,0.5)]` arbitrary value, no `backdrop-blur`).
- [x] 6.3 Per-kept-component contract is exercised by the same `ui.test.tsx` smoke pass — Tabs is rendered with both an active and inactive trigger and asserted to carry no forbidden classes; Dialog/Popover/Tooltip/ScrollArea wrap thin Radix anatomy and re-render the same protected token surface.

## 7. API client + data hooks

- [x] 7.1 `frontend/lib/api/client.ts` injects `X-API-Key` from `NEXT_PUBLIC_WEB_API_KEY` and `X-CSRF-Token` (from in-memory `setCsrfToken`) on mutating verbs only; cookie itself is HttpOnly so the token comes from `GET /csrf-token`'s JSON body. Always sends `credentials: "include"`. Throws `ApiError` on non-2xx.
- [x] 7.2 Typed wrappers in `frontend/lib/api/endpoints.ts` cover `/stats`, `/nodes`, `/nodes/countries`, `/nodes/{id}/geo`, `/scans` (POST), `/scans/{job_id}`, `/vulnerabilities`, `/csrf-token`. `getNodeByIp` is a v0 list-and-scan helper (parity debt D10 item 1; real `GET /nodes/by-ip/{ip}` deferred to `align-cli-api-palette-grammar`). `fetchProtected` parses `402 + WWW-Authenticate: L402 macaroon=..., invoice=...` into the discriminated `ProtectedResult<T>`; `fetchL402Example` binds it to `/l402/example`.
- [x] 7.3 SWR hooks in `frontend/lib/hooks/`: `useStats` (30s `refreshInterval` + `refreshWhenHidden: false` gates background tabs), `useNodes` (stable sorted-key cache identity), `useNodeDetail` (IP → list-and-scan → `/geo`), `useScanJob` (10s polling that auto-stops at `completed`/`failed`), `useCsrfToken` (immutable bootstrap). Covered by `lib/__tests__/api-client.test.ts` (9 cases: header injection, CSRF gating, L402 discrimination, error paths).

## 8. Explorer view

- [x] 8.1 `frontend/app/page.tsx` composes the five strips: `TopNav` (brand + ⌘K hint), `QueryBar` (rendered with empty query — input controller lands in 8.2), `StatsStrip` (live), `NodeTablePlaceholder` (column headers + §8.4 status note), `ExplorerFooter` (`/` focus + ⌘K palette hints; scan trigger reserved for 8.5). Brand mark in `components/brand/Brand.tsx` per the primary-allowlist rule. 9 vitest cases covering Brand, TopNav, NodeTablePlaceholder, ExplorerFooter.
- [ ] 8.2 Wire query bar grammar (`risk:`, `country:`, `exposed:`, `tor:`) to the API client; values flowing through the controlled colour rules (alert/ok/text)
- [x] 8.3 `frontend/components/explorer/StatsStrip.tsx` consumes `useStats` and renders TOTAL/EXPOSED/STALE>{N}D/TOR/OK with footer (last scan + build). Backend gap closed in 8.3a — `/api/v1/stats` now returns `exposed_count`/`stale_count`/`tor_count`/`ok_count` + `stale_threshold_days` (env `STALE_THRESHOLD_DAYS`, default 7). **Delta arrows deferred**: the spec's "rising EXPOSED is bad → alert delta" needs a baseline that today only exists for total/critical/vulnerable on `Scan`; reintroduce when `Scan` snapshots grow exposed/stale/tor/ok. `StatTile` already supports `DeltaDirection`. 7 vitest cases on the component.
- [x] 8.4 `frontend/components/explorer/NodeTable.tsx` consumes `useNodes(sort_by, sort_dir)`. Sortable headers (IP/PORT/VERSION/CC/RISK) use `Glyph caret` rotated 180° for asc; FLAGS not sortable. Each row: chevron + IP, port (alert when exposed), version, country code, risk level, FLAGS pills (EXPOSED / STALE>7d / TOR / CVE). Inline expansion via `TableExpandedRow` with state border = `RISK_TO_STATE` (CRITICAL/HIGH→alert, MEDIUM→warn, LOW→ok); body shows hostname, last_seen, asn, country, user-agent, tags. Loading / empty / error states distinct. Replaces `NodeTablePlaceholder`. STALE threshold mirrored at 7d (matches backend default; comment links to /api/v1/stats `stale_threshold_days`). 11 vitest cases.
- [ ] 8.5 Implement scan-trigger affordance in the explorer footer/query bar; wire to `useScanJob` with 10s polling

## 9. Command palette

- [ ] 9.1 Implement global `⌘K` / `Ctrl+K` listener at the app root; ignore the shortcut when an input has focus and the user is mid-typing a query
- [ ] 9.2 Implement command groups for the v0 set (intersection of CLI and REST, finalised in 1.5)
- [ ] 9.3 Implement keyboard navigation (`↑`/`↓` wrap, `↵` execute, `Esc` close); ensure focus returns to the previously focused element on close
- [ ] 9.4 Add a CI test (palette-REST parity) that asserts every non-`NAV` palette command resolves to a registered REST endpoint; commands in the `NAV` group are skipped. Output the unmatched command name on failure.

## 10. Node detail drawer

- [ ] 10.1 Implement drawer layout: sliver (180px, opacity 0.45 with active row at full opacity) + main panel
- [ ] 10.2 Implement drawer header (meta row, IP+port with port in `alert` when exposed, copy action, subtitle in `meta`/`muted`, close `✗` glyph)
- [ ] 10.3 Implement tabs row with count badges; CVE count renders in `alert` when nonzero
- [ ] 10.4 Implement the three cards: open ports (3-col grid), vulnerabilities (CVE pills with severity), cross-references
- [ ] 10.5 Implement footer action row with right-anchored `button-l402`; wire click to fetch the bound protected resource (v0: `GET /api/v1/l402/example`); on a `402` response whose `WWW-Authenticate` header begins with `L402 `, surface an inline `· l402 not yet available` note (no modal)
- [ ] 10.6 Implement focus trap and `Esc`-to-close; sliver row activation swaps detail in place without dismissing the drawer

## 11. Cutover and cleanup

- [ ] 11.1 Remove `src/web/static/index.html` and any `StaticFiles` mount in `src/web/main.py` that referenced it
- [ ] 11.2 Update `README.md`, `SETUP_INSTRUCTIONS.md`, `docs/design/README.md`, and `CLAUDE.md` to document the two-toolchain workflow (uv/pip + pnpm) and the new `frontend/` location
- [ ] 11.3 Update the project overview in `CLAUDE.md`'s "Architecture" section to reflect the Next.js dashboard living at `frontend/`, with FastAPI no longer serving HTML
- [ ] 11.4 Remove any references to `index.html` or `StaticFiles` in tests; add an integration test that `GET /` returns a 302 to `FRONTEND_ORIGIN`
- [ ] 11.5 File the follow-up changes: `align-cli-api-palette-grammar` (parity work — see D10's parity-debt list: add `GET /nodes/by-ip/{ip}`, add CLI flags for non-stats palette commands, promote `db-stats` → `stats`, decide REST status of `db-trends`/`db-export`/`db-import`/`enrich-geo`/`--check-credits`) and `l402-payment-flow` (real L402 macaroon + Lightning invoice issuance replacing the placeholder 402 challenge)

## 12. Verification

- [ ] 12.1 Run `pnpm --filter frontend lint typecheck build` cleanly
- [ ] 12.2 Run `pytest tests/` cleanly with the CORS, CSRF, redirect, and L402 stub changes
- [ ] 12.3 Run the visual-regression suite for the three views and confirm token snapshots match
- [ ] 12.4 Run `openspec validate redesign-dashboard-design-system` and confirm zero errors before `/opsx:apply`
