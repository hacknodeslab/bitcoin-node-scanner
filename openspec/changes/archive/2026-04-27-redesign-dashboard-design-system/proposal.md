## Why

The current operator dashboard is a single static `src/web/static/index.html` served by FastAPI: vanilla CSS, ad-hoc colours, no shared tokens, no controlled component vocabulary. `/DESIGN.md` and `docs/design/dashboard-v0.html` define an OSINT-terminal design system (JetBrains Mono only, semantic colour, sharp corners, controlled pill vocabulary, Unicode glyphs) that the existing surface does not implement. Operators investigating exposed RPCs, stale Core versions, and Tor nodes need a denser, terminal-grade UI that signals "tool, not SaaS"; the present dashboard reads as a generic admin panel and lacks the three first-class workspaces the design system describes (explorer, command palette, node detail drawer).

This change replaces the dashboard with a Next.js + Tailwind + shadcn/ui implementation that treats `/DESIGN.md` as the binding contract and `docs/design/dashboard-v0.html` as the visual spec.

## What Changes

- **BREAKING:** Replace `src/web/static/index.html` (vanilla HTML/CSS/JS) with a Next.js application living at `frontend/` in this monorepo. FastAPI no longer serves the dashboard HTML at `GET /`; the API surface (`/api/v1/*`) is unchanged and the new frontend consumes it as an external client.
- Bootstrap a Next.js (App Router) + Tailwind + shadcn/ui project under `frontend/`, with JetBrains Mono wired via `next/font/google` as the only typeface (Inter and any other font are removed from defaults).
- Encode `/DESIGN.md` tokens (colours, typography, spacing, components) into Tailwind's `theme.extend` so every utility maps to a token. shadcn/ui defaults are overridden — `/DESIGN.md` wins on every conflict.
- Apply hard rules across the codebase:
  - All `rounded-*` resolve to `rounded-none`. No exceptions.
  - No shadows, gradients, blurs, glassmorphism, or backdrop filters in any component (the only translucent surface allowed is the `rgba(0,0,0,0.5)` backdrop dim under the open command palette).
  - Colour is semantic. Every rendered colour traces to a `/DESIGN.md` token; decorative colour is a lint failure.
  - Replace any icon library with the Unicode glyph set defined in `/DESIGN.md` (`›`, `⌄`, `●`, `⚡`, `⌕`, `✗`, `⚠`, `·`, `⌘`).
- Implement three views matching `docs/design/dashboard-v0.html`:
  - **Explorer**: top nav, query bar, 5-tile stats strip, dense node table (9px row padding) with inline expansion.
  - **Command palette**: ⌘K-triggered overlay with grouped commands and focused-item left border in `primary`.
  - **Node detail drawer**: sliver + main panel, port list, exposure findings, CVE cards, cross-references, footer actions.
- Introduce a `Pill` component whose `kind` prop is a TypeScript discriminated union over the controlled vocabulary `'EXPOSED' | 'STALE' | 'TOR' | 'CVE' | 'OK'`. Custom strings cannot be passed; adding a new pill word is a design system change, not a feature flag.
- Provide an L402 button component (`button-l402` token) and reserve it as the only "loud" CTA. Bitcoin orange usage is capped at brand mark, focused tab indicators, and L402 affordances — out-of-policy usage is a lint failure.

## Capabilities

### New Capabilities

- `dashboard-design-system`: Token contract between `/DESIGN.md` and the Next.js codebase. Defines how YAML tokens (colours, typography, spacing, component variants) are surfaced as Tailwind theme entries and TypeScript constants; encodes the controlled pill vocabulary as a discriminated union; specifies the JetBrains Mono setup via `next/font/google`; bans rounded corners, shadows, gradients, blurs, glassmorphism, and decorative colour at the lint/CI level; defines the allowed Unicode glyph set.
- `dashboard-explorer-view`: Behavioural and visual contract for the explorer surface — top nav, query bar grammar (`prompt`, `k`, `eq`, `v-green`, `v-red`), 5-tile stats strip, dense node table with inline row expansion, and footer keyboard hints.
- `dashboard-command-palette`: ⌘K-triggered overlay. Defines invocation, focus management, command grouping, focused-item visual treatment (2px `primary` left border), keyboard navigation, and the rule that every palette entry maps 1:1 to a CLI flag and a REST endpoint.
- `dashboard-node-detail-drawer`: Drawer with sliver of recent nodes + main panel. Defines tabs, port list, exposure findings card with state-coloured 2px left border, CVE cards, cross-reference rows, and footer actions including the right-anchored L402 button.

### Modified Capabilities

- `web-dashboard`: All existing requirements about the dashboard's location, build process, fonts, colour usage, and component shapes are replaced. The dashboard is no longer served by FastAPI from `src/web/static/index.html`; it is a Next.js app at `frontend/` consuming `/api/v1/*`. Existing requirements about *what data* is shown (stats, node table, scan trigger, sortable headers, geo enrichment, CVE display) are preserved at the requirement level but their visual contract is rewritten to match `/DESIGN.md`.

## Impact

- **New code**: `frontend/` directory (Next.js 15+ App Router, Tailwind 3.4+, shadcn/ui CLI artefacts, TypeScript strict). New `package.json`, `tailwind.config.ts`, `next.config.ts`, `tsconfig.json` at `frontend/` root.
- **Removed code**: `src/web/static/index.html` and any FastAPI route that mounts it (`StaticFiles` + `GET /` redirect / catch-all). The CSRF cookie endpoint and all `/api/v1/*` endpoints stay untouched.
- **Backend impact**: The FastAPI app loses its HTML surface but keeps its API surface. CORS configuration must allow the Next.js dev origin (e.g. `http://localhost:3000`) and the production frontend origin. The CSRF double-submit cookie SHALL be set with `samesite="lax"` uniformly across all environments. A new L402 challenge helper SHALL be added that emits `402 Payment Required` with `WWW-Authenticate: L402 macaroon="<placeholder>", invoice="<placeholder>"` on protected resources, exercised by one example endpoint `GET /api/v1/l402/example`.
- **CI**: New jobs for `frontend/` — `pnpm lint`, `pnpm typecheck`, `pnpm build`. ESLint custom rules to enforce the hard design rules (no `rounded-[^n]`, no `shadow-*`, no `blur-*`, no `bg-gradient-*`, no font imports other than JetBrains Mono, no Pill string literals outside the union).
- **Docs**: `README.md`, `SETUP_INSTRUCTIONS.md`, and `docs/design/README.md` updated with the two-toolchain workflow (uv/pip + pnpm). `CLAUDE.md` updated to reflect the new architecture line.
- **Out of scope**: L402 payment flow integration (button is rendered, click target is stubbed and routed to a TODO endpoint — full L402 plumbing is a separate change). No landing page, no onboarding, no auth UI redesign.

## Open Questions

These are surfaced rather than decided so they can be resolved in `design.md` or before `/opsx:apply`:

1. **shadcn anatomy vs. owned primitives.** Do we keep shadcn's component anatomy (Radix primitives + our token-mapped styles) for `Dialog`, `Command`, `Tabs`, `Popover`, etc., or fork the small set we use (`Pill`, `Button`, `Input`, `Card`, `Tabs`, `CommandPalette`, `Drawer`) into `frontend/components/ui/` that we own outright? Trade-off: keeping shadcn means free Radix accessibility and upstream patches, but every upgrade risks a token regression; forking pins our visual contract but transfers a11y maintenance to us.
2. **Token surface: CSS custom properties or Tailwind theme only.** Do we mirror tokens as CSS custom properties on `:root` (so non-Tailwind code paths — third-party widgets, runtime themes, embedded SVGs — can read them), or do we rely solely on Tailwind's `theme.extend` and trust that nothing renders outside Tailwind's reach? Mixed approach is also on the table (CSS vars as the source of truth, Tailwind theme as a thin facade).
3. **L402 boundary.** *Resolved (2026-04-25):* adopt the standard L402 convention. The button targets the protected resource it is bound to; the backend responds with `402 Payment Required` and `WWW-Authenticate: L402 macaroon="<placeholder>", invoice="<placeholder>"` until the real L402 capability lands. One example protected endpoint (`GET /api/v1/l402/example`) ships in this change so CI exercises the path. Full payment flow remains a separate `l402-payment-flow` change. See `design.md` D9.
4. **CORS / CSRF cross-origin.** *Resolved (2026-04-25):* `samesite="lax"` uniformly across dev, staging, and production. CORS allows `FRONTEND_ORIGIN` for `/api/v1/*` and the CSRF token endpoint. No `CSRF_SAMESITE` env var. See `design.md` D8.
5. **API parity guarantee for the command palette.** *Resolved (2026-04-25):* every non-`NAV` palette command MUST have a REST endpoint; CLI parity is tracked as debt in the follow-up `align-cli-api-palette-grammar`. The strict three-way intersection was rejected as unusable (only two commands). The v0 palette command set is frozen in `design.md` D10. The original rule in `/DESIGN.md` will be reformulated in a small documentation-only change after this redesign lands.
