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

- [ ] 5.1 Implement `Pill.tsx` whose `kind` prop is the discriminated union `{kind:'EXPOSED'} | {kind:'STALE'} | {kind:'TOR'} | {kind:'CVE',severity:'low'|'medium'|'high'|'critical'} | {kind:'OK'}`; map each variant to fixed token-derived colours and `padding: 2px 7px`
- [ ] 5.2 Implement `Button.tsx` with two variants only: `secondary` (default) and `l402`; hover on secondary changes only text colour; l402 prefixes a `⚡` glyph and uses `button-l402` tokens
- [ ] 5.3 Implement `Input.tsx` (`input-query` token), `Card.tsx` (`card` token), `StatTile.tsx` (`stat-tile` token with delta colour rule)
- [ ] 5.4 Implement `Glyph.tsx` with a string-literal `name` union covering `chevron`, `caret`, `dot`, `bolt`, `search`, `cross`, `warn`, `sep`, `cmd`, mapping to `›`, `⌄`, `●`, `⚡`, `⌕`, `✗`, `⚠`, `·`, `⌘`
- [ ] 5.5 Implement `TableRow.tsx` (9px vertical / 14px horizontal padding, no hover background) and `TableExpandedRow.tsx` (state-coloured 2px left border, `surface` background, 32px left padding for the findings body)
- [ ] 5.6 Implement `QueryBar.tsx` parsing `key=value` tokens and applying the controlled colour map (key→muted, eq→dim, value→text/ok/alert)
- [ ] 5.7 Implement `Tabs.tsx` with `meta` typography, active tab in `text` colour with 1px `primary` bottom border (the only place outside brand/L402 where `primary` is allowed)
- [ ] 5.8 Implement `Drawer.tsx` (sliver + main panel, focus trap, keyboard navigation) and `CommandPalette.tsx` (⌘K trigger, flat alpha backdrop, grouped commands, single-line items)
- [ ] 5.9 Add Storybook (or a lightweight stories file) for each owned primitive; render a snapshot test asserting computed `border-radius: 0` and a font-family that resolves to JetBrains Mono

## 6. shadcn keep-list overrides

- [ ] 6.1 Add `Dialog`, `Popover`, `Tabs` (Radix), `Tooltip`, `ScrollArea` via `pnpm dlx shadcn@latest add <name>`
- [ ] 6.2 Edit each generated component to strip `rounded-*`, `shadow-*`, gradient utilities, decorative greys; replace with token-mapped utilities
- [ ] 6.3 Add a snapshot test per kept component asserting computed `border-radius: 0` and that no `box-shadow` is applied

## 7. API client + data hooks

- [ ] 7.1 Add `frontend/lib/api/client.ts` with a typed fetch wrapper that injects `WEB_API_KEY` and the CSRF header (`X-CSRF-Token`), reading the cookie value at request time
- [ ] 7.2 Add typed wrappers for `GET /api/v1/stats`, `GET /api/v1/nodes`, `GET /api/v1/nodes/countries`, `GET /api/v1/nodes/{ip}`, `POST /api/v1/scans`, `GET /api/v1/scans/{job_id}`, `GET /api/v1/csrf-token`. Add a generic `fetchProtected(url)` helper that recognises `402` + `WWW-Authenticate: L402 ...` responses and returns a discriminated result `{ kind: 'ok', data } | { kind: 'l402-challenge', macaroon, invoice }`
- [ ] 7.3 Add React hooks (`useStats`, `useNodes`, `useNodeDetail`, `useScanJob`, `useCsrfToken`) using SWR or React Query; include the 30s refresh and tab-foreground gate for `useStats`

## 8. Explorer view

- [ ] 8.1 Implement `frontend/app/page.tsx` rendering the explorer layout: top nav, query bar, stats strip, table, footer
- [ ] 8.2 Wire query bar grammar (`risk:`, `country:`, `exposed:`, `tor:`) to the API client; values flowing through the controlled colour rules (alert/ok/text)
- [ ] 8.3 Wire stats strip to `useStats` with the five tokens (TOTAL, EXPOSED, STALE, TOR, OK); apply the "rising EXPOSED is bad → alert delta" rule
- [ ] 8.4 Wire node table to `useNodes`; implement sortable headers using `Glyph` (no `▲`/`▼`/`⇅` Unicode arrows); implement inline row expansion with state-coloured 2px left border
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
