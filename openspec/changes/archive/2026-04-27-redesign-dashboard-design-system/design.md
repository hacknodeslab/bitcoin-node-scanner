## Context

The dashboard today is a single `src/web/static/index.html` file (≈900 lines, vanilla HTML + scoped `<style>` + vanilla JS using `fetch`) served by FastAPI as a static asset. It pre-dates the design system codified in `/DESIGN.md` and visualised in `docs/design/dashboard-v0.html`. The visual contract differs in nearly every dimension that matters: the existing dashboard uses Inter-like system fonts, rounded corners (`border-radius: 8px` on cards), drop shadows in places, ad-hoc colour values, a single grid view (no command palette, no detail drawer), and pill labels driven by free-form strings.

`/DESIGN.md` is the source of truth for tokens (YAML front matter) and rationale (prose). `docs/design/dashboard-v0.html` is the source of truth for layout, density, and component composition for the three target views. Both documents are in-tree and treated as binding by this change.

The chosen implementation stack is Next.js (App Router) + Tailwind + shadcn/ui, living at `frontend/` in this monorepo. Nothing in this stack exists today — the change includes bootstrap.

The FastAPI backend (`src/web/`) keeps its `/api/v1/*` surface unchanged. The CSRF endpoint and double-submit cookie pattern need adjustment for cross-origin operation (see Decisions and the recently fixed `secure=request.url.scheme == "https"` in `src/web/routers/csrf.py`).

## Goals / Non-Goals

**Goals:**

- Replace the current dashboard with a Next.js application at `frontend/` that visually and behaviourally matches `docs/design/dashboard-v0.html` and respects every token in `/DESIGN.md`.
- Make `/DESIGN.md` machine-binding: tokens flow into Tailwind's `theme.extend` (and optionally CSS custom properties) so violations are caught by the linter, not by code review.
- Encode the controlled pill vocabulary as a TypeScript discriminated union so adding a new pill word requires editing the design system, not a feature commit.
- Cap Bitcoin orange usage and ban decorative colour, rounded corners, shadows, gradients, blurs, glassmorphism, and font imports other than JetBrains Mono — at lint level, not by convention.
- Ship the three target views (explorer, command palette, node detail drawer) wired to the existing `/api/v1/*` endpoints, with no regression in functionality the current dashboard already provides (stats, node table, sortable headers, scan trigger, filters).
- Keep the L402 button visible and well-formed wherever the design calls for it, even though the payment flow itself is out of scope.

**Non-Goals:**

- Landing page, marketing surfaces, onboarding, sign-up, pricing.
- Auth UI redesign. The `WEB_API_KEY` header pattern is preserved; only the dashboard surface changes.
- Implementing the L402 payment flow (invoice generation, polling, content unlock). The button is rendered and clickable; the click target is a stubbed endpoint that returns 501.
- Migrating the FastAPI backend, the scanner, the database layer, or the CLI. They are unaffected.
- Mobile-first or responsive redesign below 960px. Operators run this on wide monitors; small-screen support follows existing best-effort behaviour.

## Decisions

### D1 — Stack: Next.js (App Router) + Tailwind 3.4+ + shadcn/ui + TypeScript strict

**Rationale.** The prompt mandates this stack. Next.js App Router gives us per-route layouts (good fit for the drawer overlay pattern) and `next/font/google` for first-class JetBrains Mono loading without FOUT. Tailwind is the most direct path from a YAML token contract to a constrained utility surface. shadcn/ui gives Radix-based primitives (Dialog, Command, Tabs, Popover) we need for the palette and drawer without committing us to its visual defaults — we override them.

**Alternatives considered.** (a) Keep vanilla HTML and apply tokens to the existing `index.html`. Rejected: rules like "TypeScript discriminated union for pills" and "next/font/google" don't apply, and the three views need real client-side state. (b) Vite + React + Tailwind. Rejected: loses Next.js's font primitive and SSR/edge rendering options that may matter later.

### D2 — `/DESIGN.md` wins on every conflict with shadcn defaults

**Rationale.** shadcn ships with rounded corners, soft shadows, decorative greys, and Inter as the default font. All of these violate `/DESIGN.md`. We treat shadcn as a *primitive* layer (Radix wrappers + headless behaviour) and replace its style layer wholesale. We do this by:

1. Running `pnpm dlx shadcn@latest init` with our own `tailwind.config.ts` already in place so the CLI does not seed its own theme.
2. After each `shadcn add <component>`, immediately editing the generated file to strip `rounded-*`, `shadow-*`, gradient utilities, and any colour token not in our theme.
3. CI-level lint rules (see D5) that fail the build if those utilities reappear.

### D3 — Token surface: Tailwind `theme.extend` is canonical, CSS custom properties mirror

**Rationale.** Tailwind's theme is the most direct enforcement point — utilities outside the theme don't compile, which catches "did you mean to use a token" violations. But Radix and embedded SVGs sometimes render outside Tailwind's reach (data-attribute styling, `dangerouslySetInnerHTML`, third-party charts). To cover both, we do:

- Define tokens once in a TypeScript module (`frontend/lib/design-tokens.ts`) parsed from a static import of the YAML in `/DESIGN.md` at build time (via a tiny build script that emits a `.ts` file).
- Tailwind config imports from that module to populate `theme.extend.colors`, `theme.extend.fontFamily`, `theme.extend.spacing`, `theme.extend.borderRadius`, etc.
- A `globals.css` `@layer base` block emits the same tokens as CSS custom properties on `:root`, so non-Tailwind code can read `var(--color-alert)`.

This resolves Open Question #2 from the proposal in favour of a mirrored approach with Tailwind as the lint surface.

**Alternatives considered.** (a) Tailwind only. Rejected: leaks for the cases above. (b) CSS variables only. Rejected: loses Tailwind's compile-time enforcement, which is the strongest lever we have against decorative colour.

### D4 — Component anatomy: keep shadcn for what we don't customise, fork for what we do

**Rationale.** This resolves Open Question #1 from the proposal as a hybrid:

- **Keep shadcn anatomy** (Radix primitives + our token-mapped styles) for: `Dialog`, `Popover`, `Tabs`, `Tooltip`, `ScrollArea`. These are headless-ish primitives where the a11y heavy lifting matters and our visual changes are small (mostly removing rounding/shadow).
- **Fork into `frontend/components/ui/`** (we own outright) for: `Pill`, `Button`, `Card`, `Input`, `StatTile`, `TableRow`, `CommandPalette`, `Drawer`, `QueryBar`. These are the components where our visual contract is the whole point — Pill is a discriminated union, Button has a hard cap on Bitcoin orange usage, StatTile has a token-bound delta colour rule.

The fork list is small enough to maintain; the keep list is small enough to audit on shadcn upgrades.

### D5 — Hard rules enforced at lint time, not at review

**Rationale.** Convention rots; lint doesn't. We add ESLint rules (custom, in `frontend/eslint-rules/`) that fail CI on any of:

- `className` containing `rounded-` (anything other than `rounded-none`).
- `className` containing `shadow-`, `blur-`, `backdrop-`, `bg-gradient-`.
- A `next/font` import that loads anything other than `JetBrains_Mono`. A separate rule bans `import` from `@fontsource/*`, `next/font/google` for any other family, and `<link rel="stylesheet" href="...fonts.googleapis...">` outside the JetBrains Mono entry.
- `<Pill kind="…">` where the value is not a member of the discriminated union (TypeScript handles this for type-checked call sites; the lint rule catches dynamic strings cast as `any`).
- Inline `style={{color: …}}` and `style={{backgroundColor: …}}` with values not present in the token module.
- Bitcoin orange used outside an allow-list of identifiers (brand mark, focused tab indicator, `button-l402`). This is approximated by a rule that flags any `text-primary`, `bg-primary`, `border-primary` usage outside files in `frontend/components/brand/`, `frontend/components/ui/Button.tsx` (l402 variant), and `frontend/components/ui/Tabs.tsx`.
- Imports from `lucide-react`, `@heroicons/*`, `react-icons`, or any icon library. Glyphs come from the allow-list `›`, `⌄`, `●`, `⚡`, `⌕`, `✗`, `⚠`, `·`, `⌘` in a `Glyph` component.

### D6 — Pills as a discriminated union

**Rationale.** Mandated by the prompt. Concretely:

```ts
type PillKind =
  | { kind: 'EXPOSED' }   // alert
  | { kind: 'STALE' }     // alert
  | { kind: 'TOR' }       // warn
  | { kind: 'CVE'; severity: 'low' | 'medium' | 'high' | 'critical' }
  | { kind: 'OK' };       // ok

export function Pill(props: PillKind): JSX.Element { … }
```

Each `kind` resolves to a fixed colour pair (`alert` + `alert-bg`, `warn` + `warn-bg`, `ok` + `ok-bg`) at compile time. The CVE variant carries a severity discriminator so the colour can shift to `warn` for low/medium and `alert` for high/critical without admitting a free-form string. Adding a new pill is an explicit edit to this union — caught by code review and by tests that snapshot the rendered set.

### D7 — Glyphs over icons

**Rationale.** Mandated by the prompt. We expose them as a tiny enum-backed component:

```tsx
<Glyph name="chevron" />   // ›
<Glyph name="caret" />     // ⌄
<Glyph name="dot" />       // ●
<Glyph name="bolt" />      // ⚡
<Glyph name="search" />    // ⌕
<Glyph name="cross" />     // ✗
<Glyph name="warn" />      // ⚠
<Glyph name="sep" />       // ·
<Glyph name="cmd" />       // ⌘
```

`name` is a string literal union. Direct Unicode usage in JSX is allowed but linted to nudge towards `<Glyph>` for grep-ability.

### D8 — Backend integration: API at a separate origin, CSRF via lax cookie (uniform)

**Rationale.** Resolves Open Question #4 and the production-posture follow-up. Two-origin operation is the simplest production topology and the dev story is straightforward (frontend on `:3000`, FastAPI on `:8000`). To make CSRF work cross-origin without weakening the double-submit pattern:

- `src/web/routers/csrf.py` switches the cookie to `samesite="lax"` **uniformly across all environments** (dev, staging, production). The double-submit check still requires a matching `X-CSRF-Token` header, which an attacker on a third-party origin cannot read or set on cross-site requests; the `lax` setting only governs whether the cookie is sent, not whether the header check passes.
- FastAPI CORS allows the configured frontend origin (`FRONTEND_ORIGIN` env var, defaulting to `http://localhost:3000` in dev).
- Even when production deployment unifies frontend and API behind a single reverse proxy (e.g. Caddy), the cookie stays at `lax`. We pay a marginal hardening cost in exchange for one knob, one configuration, and a behavioural model that does not bifurcate by environment. No `CSRF_SAMESITE` env var.

### D9 — L402 boundary: button + standard 402 challenge convention

**Rationale.** Resolves Open Question #3 in favour of the standard L402 convention (HTTP 402 challenge with `WWW-Authenticate: L402 macaroon=..., invoice=...`), not a bespoke `/api/v1/l402/invoice` POST endpoint. L402 is challenge-response over HTTP 402 — a payment-required resource is the protected URL itself, not a parallel "create invoice" endpoint. Adopting the convention now means the L402 implementation later wires real macaroons and Lightning invoices into the same response shape, with no URL renaming and no shim to delete.

Concretely, this change ships:

- A FastAPI dependency / helper that emits an HTTP 402 response with header `WWW-Authenticate: L402 macaroon="<placeholder>", invoice="<placeholder>"` and body `{"error": "l402_pending"}`. Until the real L402 capability lands, the placeholders are static strings clearly marked as such.
- One example protected endpoint exercising the helper, e.g. `GET /api/v1/l402/example`. This exists so CI tests can exercise the 402 + `WWW-Authenticate` path end-to-end and so the drawer's L402 button has a real target to click against today.
- The drawer's L402 button targets the protected resource it is bound to. In v0, the only bound resource is the example endpoint; subsequent changes that introduce premium content (per-node deep-scan reports, historical timelines, etc.) bind the button to those endpoints, and each emits the same 402 challenge until the L402 capability is fully implemented.
- The frontend treats any 402 with a `WWW-Authenticate: L402 ...` header as "L402 challenge received". Since v0 lacks a payment client, it surfaces a non-blocking inline note (`· l402 not yet available`) in `meta` typography and `dim` colour next to the button, without raising a modal.

The full L402 payment flow (macaroon issuance, Lightning invoice generation, status polling, content unlock) remains a separate change (`l402-payment-flow`).

### D10 — Palette ↔ REST is enforced now; palette ↔ CLI parity is tracked debt

**Rationale.** Resolves Open Question #5. `/DESIGN.md` mandates a 1:1 mapping between palette entries, CLI flags, and REST endpoints. An inventory (2026-04-25) showed the strict three-way intersection contains effectively two commands (`scan: start`, `stats: show`) — a palette built on it would be unusable. The design rule is honoured in spirit, not in form, by reformulating it as follows:

> Every command in the palette MUST have a corresponding REST endpoint with consistent grammar. CLI parity is a design-system goal tracked as debt in the follow-up change `align-cli-api-palette-grammar`. Commands without a REST endpoint MUST NOT enter the palette.

The palette is, by definition, the dashboard's surface for the API — REST is the contract. The CLI is *also* meant to mirror that contract; today it lags, and we accept the asymmetry in v0 rather than ship an empty palette or expand the CLI as a side-effect of a frontend change.

The recommended update to `/DESIGN.md` (to be made as a small documentation change shortly after this redesign lands) is to replace the "matching CLI flag and REST endpoint" sentence with the rule above and add a single bullet pointing at the `align-cli-api-palette-grammar` change as the parity tracker.

**V0 palette command set** (frozen 2026-04-25):

```
SCAN
  scan: start                  → POST /api/v1/scans
  scan: status <job_id>        → GET  /api/v1/scans/{job_id}

STATS
  stats: show                  → GET  /api/v1/stats
  stats: refresh               → GET  /api/v1/stats  (force refetch)

NODES
  node: list                   → GET  /api/v1/nodes
  node: filter risk <level>    → GET  /api/v1/nodes?risk_level=<level>
  node: filter country <code>  → GET  /api/v1/nodes?country=<code>
  node: open <ip>              → GET  /api/v1/nodes  (resolve ip→id), then GET /api/v1/nodes/{id}/geo for the drawer
  node: countries              → GET  /api/v1/nodes/countries
  node: clear filters          → reset query bar tokens, refetch /nodes

VULNERABILITIES
  vuln: list                   → GET  /api/v1/vulnerabilities

NAV  (frontend-only — exempt from REST mapping by design)
  go: explorer                 → navigate to '/'
  drawer: close                → close the open drawer
  drawer: copy ip              → copy the active drawer's IP to clipboard
  palette: close               → close the palette (also: Esc)
```

The `node: open <ip>` flow currently has to resolve IP → numeric id by scanning the `/nodes` list, because the REST surface lacks a `GET /nodes/by-ip/{ip}` endpoint. This shortcut works for v0 (databases under ~100k nodes) and is captured as the first entry on the parity-debt list:

- **Parity debt to track in `align-cli-api-palette-grammar`:**
  1. Add `GET /api/v1/nodes/by-ip/{ip}` so `node: open <ip>` is one round-trip.
  2. Add CLI flags for: `node-list`, `node-filter-risk`, `node-filter-country`, `node-countries`, `vuln-list`, `scan-status JOB_ID`. Names are illustrative; the alignment change will pick the canonical grammar.
  3. Promote `db-stats` → `stats` in the CLI grammar.
  4. Decide whether `db-trends`, `db-export`, `db-import`, `enrich-geo`, `--check-credits` get REST endpoints (so they enter the palette) or remain CLI-only operator tools (so they stay out).

**Alternatives considered.** (a) Strict three-way intersection — rejected for unusability. (b) Expand CLI in this change — rejected for scope creep into a non-frontend area. The chosen path keeps this change frontend-shaped while documenting the debt explicitly.

## Risks / Trade-offs

- **Risk:** shadcn upgrades reintroduce rounding or shadow defaults in components we kept. **Mitigation:** D5 lint rules run on every PR; shadcn upgrades are explicit, not transitive (`pnpm dlx shadcn@latest add <name>` is opt-in per component).
- **Risk:** Operators on slow networks see a flash of unstyled content while JetBrains Mono loads. **Mitigation:** `next/font/google` with `display: 'swap'` and a monospace fallback (`ui-monospace, SFMono-Regular, Menlo, Consolas`) — already the convention in `dashboard-v0.html`.
- **Risk:** The two-origin setup breaks the existing dashboard's CSRF flow during the transition window. **Mitigation:** The transition is atomic — we delete `index.html` and the FastAPI mount in the same change as the new frontend lands. There is no "half-migrated" state in a deployed environment.
- **Risk:** Tailwind theme extension diverges from `/DESIGN.md` over time as people edit one without the other. **Mitigation:** D3's build-time codegen (`design-tokens.ts` generated from `/DESIGN.md`) makes the YAML the single source. A CI job re-runs the codegen and fails if the committed file is stale.
- **Risk:** Radix primitives ship behaviours (focus rings, animation timings) that conflict with the system's "no decoration" rule. **Mitigation:** Per-component override pass; focus rings remain (a11y) but use `outline` in `border` colour with no offset glow.
- **Trade-off:** Forking 9 components increases our surface area but is the only way to enforce the discriminated-union pill, the Bitcoin-orange cap, and the glyph-over-icon rule without fighting shadcn on every upgrade.
- **Trade-off:** Deleting `index.html` breaks any deployment that pinned to `GET /` for the dashboard. We document the cutover in the migration plan and provide a redirect (FastAPI returns 302 to `FRONTEND_ORIGIN`) for backward compatibility during a deprecation window — to be removed once external bookmarks are gone.

## Migration Plan

1. **Land the change behind a flag.** Add `frontend/` and the new code without removing `src/web/static/index.html`. FastAPI keeps serving the old dashboard.
2. **Stand up the new surface in staging.** Deploy `frontend/` to a staging origin. Validate the three views, the CSRF flow, the scan trigger end-to-end against staging FastAPI.
3. **Cutover.** In a single deploy: remove the static mount from `src/web/main.py`, delete `src/web/static/index.html`, redirect `GET /` to `FRONTEND_ORIGIN`, ship the new frontend to production.
4. **Deprecation window.** The redirect on `GET /` lives for 30 days, then is removed.
5. **Rollback.** Reverting the cutover commit restores `index.html` and the static mount; the `frontend/` directory remains in tree but unserved. The CSRF cookie change (D8) is forward-compatible — `samesite=lax` works for both topologies — so it does not need rolling back.

## Open Questions

All three open questions in this design are now resolved (2026-04-25). They are kept here as decision history; the body of the design above has been updated to reflect the resolutions:

1. **Production CSRF posture.** *Resolved:* `samesite=lax` uniformly across all environments. No `CSRF_SAMESITE` env var; one configuration, one behavioural model. See D8.
2. **Codegen tooling.** *Resolved:* `yaml` (or `js-yaml`) as a dev dependency. The hand-rolled approach loses to the YAML front matter already containing token references like `"{colors.alert-bg}"` that need real parsing and resolution. The codegen script (`frontend/scripts/generate-design-tokens.ts`) imports the parser and resolves references when emitting `design-tokens.ts`.
3. **L402 endpoint shape.** *Resolved:* Adopt the standard L402 convention — HTTP 402 with `WWW-Authenticate: L402 macaroon=..., invoice=...` on the protected resource itself, not a parallel `POST /l402/invoice`. See D9.
