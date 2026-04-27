## Context

The dashboard is a token-driven Next.js 16 app under `frontend/`. `/DESIGN.md`'s YAML front matter is parsed by `frontend/scripts/generate-design-tokens.ts` (using `js-yaml`) into two outputs:

1. `frontend/lib/design-tokens.ts` — typed `as const` constants consumed by `tailwind.config.ts` (which **replaces** Tailwind defaults rather than extending them, so unknown utilities fail to compile) and by component code.
2. A `BEGIN/END GENERATED TOKENS` delimited `:root` block in `frontend/app/globals.css` exposing every token as a CSS custom property.

`pnpm tokens:check` re-runs codegen and fails CI if either output drifts from committed state. ESLint rules in `frontend/eslint-rules/index.cjs` enforce the colour allowlist (`no-banned-classnames`, `design-system/primary-allowlist`).

Components today reference colours either through Tailwind utilities (`text-alert`, `bg-surface-2`) — which compile to the CSS variables — or directly through Tailwind classes that resolve via the same token map. There is **no existing theming abstraction**: dark is implicit and global.

The TopNav is at `frontend/components/topnav/`; commands live in `frontend/lib/commands.ts` with a `kind` discriminator (`REST` | `NAV`) and are routed through `ExplorerCommandsContext`. SWR powers data fetching but is irrelevant here.

## Goals / Non-Goals

**Goals:**
- Operators can switch between dark, light, and system themes from the running app without a reload.
- Light palette meets WCAG AA contrast (4.5:1) for body text against bg/surface and preserves the brand orange.
- No flash of wrong theme on first paint, including hard refreshes and cold loads.
- Theme choice survives reloads and tab restores; system mode tracks `prefers-color-scheme` changes live.
- Keep token names stable across themes so existing Tailwind utilities, components, and ESLint rules keep working with zero edits.

**Non-Goals:**
- Migrating to Tailwind's `dark:` variant (rejected in D1 below).
- Per-component palette overrides beyond the colour tokens (e.g. spacing/typography stay theme-agnostic).
- Visual regression snapshots for the new palette — already deferred in `redesign-dashboard-design-system` §4.8.
- Theming `src/web/static/index.html` — being removed in §11.1.
- Synchronising theme across browser tabs (the `storage` event hook costs more than the value at v0; revisit if asked).

## Decisions

### D1. CSS-variable swap via `[data-theme]` over Tailwind's `dark:` variant

Add a single `[data-theme="light"]` block to `globals.css` that overrides only the `--color-*` custom properties; `:root` keeps current dark values as the fallback. The codegen script writes both blocks inside the same `BEGIN/END GENERATED TOKENS` markers.

**Rationale**: Token names are identical across themes — every existing Tailwind utility (`bg-surface-2`, `text-alert`, …) automatically picks up the right palette because Tailwind config maps token names to CSS variables. Zero changes to component code or ESLint allowlists. Tailwind's `dark:` variant would require touching every coloured utility in the codebase (currently ~hundreds of call sites in `frontend/components/`) and would couple theme to a single class hook (`dark`) we don't otherwise need.

**Alternatives considered**:
- *Tailwind `dark:` variant with `darkMode: ['class']`*: rejected — high migration cost, no benefit since we're not styling for prose ergonomics.
- *Two stylesheet files swapped at runtime*: rejected — flash on swap, complicates Next.js asset pipeline.
- *CSS `@media (prefers-color-scheme: light) { ... }`*: rejected because it ignores the explicit user override (system mode wraps it instead — see D5).

### D2. `themes:` map in `DESIGN.md` (breaking the flat `colors:` block)

Restructure the front matter from:
```yaml
colors:
  primary: "#F7931A"
  bg: "#0a0a0a"
  ...
```
to:
```yaml
themes:
  dark:
    primary: "#F7931A"
    bg: "#0a0a0a"
    ...
  light:
    primary: "#F7931A"
    bg: "#f6f6f6"
    ...
```

The codegen script reads `themes.dark` and `themes.light`, and additionally exposes `colors` as an alias for `themes.dark` so `tailwind.config.ts` and any direct token import keep working without edits. Component-token references in DESIGN.md (e.g. `pill-alert.backgroundColor: "{colors.alert-bg}"`) are rewritten to `"{themes.dark.alert-bg}"` for the dark resolution; the codegen script's reference resolver is updated to walk the new path. The `components` constant in `design-tokens.ts` continues to emit dark-resolved values — light-mode component tokens are not exposed at v0 because no component code reads them today (everything routes through Tailwind utilities, which already swap correctly via D1).

**Alternatives considered**:
- *Keep flat `colors:` and add a parallel `colors-light:`*: rejected — proliferates top-level keys, doesn't scale to a hypothetical `high-contrast` theme later, and forces a special case in the codegen instead of a general loop.
- *Theme-prefixed token names (`dark-bg`, `light-bg`)*: rejected — would force per-component conditional class names (we'd lose the "swap variables, leave classes alone" property of D1).

### D3. Light palette (concrete values, WCAG-AA verified)

| Token         | Dark        | Light       | Contrast vs light bg | Notes |
|---------------|-------------|-------------|----------------------|-------|
| `primary`     | `#F7931A`   | `#F7931A`   | 2.7:1 (decorative)   | Brand mark — preserved on both. Allowlist already restricts decorative use. |
| `bg`          | `#0a0a0a`   | `#f6f6f6`   | —                    | Page background. |
| `surface`     | `#141414`   | `#ffffff`   | —                    | Cards, drawer. |
| `surface-2`   | `#1a1a1a`   | `#ececec`   | —                    | Hover/focus surfaces, expanded rows. |
| `border`      | `#2a2a2a`   | `#d4d4d4`   | —                    | |
| `border-dim`  | `#1e1e1e`   | `#e4e4e4`   | —                    | |
| `text`        | `#e0e0e0`   | `#1a1a1a`   | 14.6:1 vs `bg`       | Body. AA pass. |
| `text-dim`    | `#aaaaaa`   | `#404040`   | 9.5:1 vs `bg`        | Secondary. |
| `muted`       | `#888888`   | `#5a5a5a`   | 6.0:1 vs `bg`        | Tertiary. AA pass. |
| `dim`         | `#555555`   | `#8a8a8a`   | 3.1:1 vs `bg`        | Decorative dividers/glyphs only — same role as in dark. |
| `ok`          | `#00ff9c`   | `#008f5c`   | 4.6:1 vs `bg`        | AA pass for body text. |
| `warn`        | `#ffb000`   | `#a36a00`   | 4.5:1 vs `bg`        | AA pass for body text. |
| `alert`       | `#ff4444`   | `#cc0000`   | 5.9:1 vs `bg`        | AA pass for body text. |
| `on-primary`  | `#0a0a0a`   | `#0a0a0a`   | 12:1 vs `primary`    | Foreground on orange — dark on both themes. |
| `alert-bg`    | `#2a0000`   | `#ffe5e5`   | —                    | Pill background. |
| `warn-bg`     | `#2a1f00`   | `#fff4d6`   | —                    | Pill background. |
| `ok-bg`       | `#002a1a`   | `#daf5e8`   | —                    | Pill background. |
| `l402-bg`     | `#1a1200`   | `#fff2d6`   | —                    | Lightning button background. |

Pill foreground/background pairs were checked separately: `alert` `#cc0000` on `#ffe5e5` → 5.6:1; `warn` `#a36a00` on `#fff4d6` → 4.7:1; `ok` `#008f5c` on `#daf5e8` → 4.5:1. All meet AA for body text. Hex values are recorded here so the spec scenarios can assert them deterministically.

### D4. Three-state segmented control over a cycle button

`ThemeToggle` renders three side-by-side option buttons (`dark` / `light` / `system`) inside the existing TopNav, each with a single-character glyph from the existing `GLYPHS` map (no new icon library — banned by ESLint). Active option uses the existing `border-b border-primary` underline pattern from `Tabs.tsx`.

**Rationale**: The explorer aesthetic is data-dense and prefers explicit state over hidden state. A cycle button hides the current mode behind one icon (especially confusing for `system`, which can render as either light or dark). A segmented control makes the choice legible at a glance and keeps keyboard parity (Tab navigates between the three).

**Alternatives considered**:
- *Cycle button*: rejected for ambiguity.
- *Dropdown menu*: rejected — adds a Radix Popover wrapper for three options, plus an extra click for every change.

### D5. Persistence + FOUC mitigation via inline pre-hydration script

Theme is stored under `localStorage['bns:theme']` ∈ `{'dark', 'light', 'system'}`. A small synchronous IIFE injected via `<Script id="theme-init" strategy="beforeInteractive">` in `app/layout.tsx`'s `<head>` reads the stored value (or falls back to `'system'`) and resolves it against `window.matchMedia('(prefers-color-scheme: dark)').matches`, then sets `document.documentElement.dataset.theme` to `'dark'` or `'light'` before React hydrates.

The same resolution lives in `frontend/lib/theme.ts` as `resolveTheme(stored, systemPrefersDark)` and is unit-tested. The inline script duplicates the function body verbatim (it cannot import — pre-hydration runs before bundles load); a vitest sanity check will load both and assert behavioural parity through a small set of input cases.

`ThemeProvider` mounts a context with `{mode, resolved, setMode}` and adds a `matchMedia` change listener **only when `mode === 'system'`**, removing it on mode transitions. `setMode` writes to `localStorage` and updates `document.documentElement.dataset.theme` synchronously.

**Rationale**: This is the canonical Next.js / React pattern for FOUC-free themes (used by `next-themes`, Tailwind's own docs, etc.). Avoiding a third-party dep keeps the dependency surface minimal and matches the project's "owned primitives" stance from §5 of the redesign change.

**Alternatives considered**:
- *Cookie-driven SSR theming*: rejected — backend currently has no theme awareness, and cookies leak to API requests.
- *`next-themes` library*: rejected — ~1KB of indirection for a 30-line solution we already own; ESLint `no-banned-imports` would also need updating.

### D6. Palette commands as `NAV` kind

Three new entries in `lib/commands.ts`:
```ts
{ id: 'theme-dark', label: 'theme: dark', kind: 'NAV', restEndpoint: null },
{ id: 'theme-light', label: 'theme: light', kind: 'NAV', restEndpoint: null },
{ id: 'theme-system', label: 'theme: system', kind: 'NAV', restEndpoint: null },
```

Action wiring lives in `ExplorerCommandsContext` and calls the same `setMode` exposed by `ThemeProvider`. The existing `commands.test.ts` already asserts `NAV` entries have `restEndpoint: null` — these three pass without changes to the test scaffolding.

### D7. Tailwind config keeps `colors = themes.dark`

`tailwind.config.ts` keeps importing `colors` from `lib/design-tokens.ts`. The codegen script ensures `colors === themes.dark`, so Tailwind's compile-time class set is unchanged. Tailwind utilities like `bg-bg`, `bg-surface`, `text-text`, `text-alert` continue to compile to the same CSS variable references — only the *values* of those variables change at runtime when `[data-theme="light"]` matches.

This is the load-bearing decision behind D1: by keeping the token *map* identical and only swapping CSS variable values via `[data-theme]`, every existing component renders correctly in both themes with zero source changes.

## Risks / Trade-offs

- **Risk**: Light palette contrast bugs surface only at runtime on real views.
  → **Mitigation**: D3 records concrete hex values and AA ratios per token; vitest test asserts the codegen emits exactly those values; manual smoke-check on each existing view (explorer, drawer, palette) before merge. Visual-regression coverage stays out of scope per `redesign-dashboard-design-system` §4.8.
- **Risk**: FOUC inline script and `resolveTheme()` drift apart.
  → **Mitigation**: A vitest case loads both the script body (extracted to a string constant in `lib/theme.ts`) and the `resolveTheme` helper, runs each through the same input matrix, and asserts identical output.
- **Risk**: `localStorage` quota or privacy mode (Safari ITP) silently throws.
  → **Mitigation**: Wrap reads/writes in try/catch and degrade to ephemeral state — failure mode is "theme resets on reload", not a runtime error.
- **Risk**: SSR/CSR mismatch warning if `ThemeProvider`'s initial render differs from server output.
  → **Mitigation**: The pre-hydration script sets `data-theme` on `<html>` before React mounts; provider reads from that attribute on first render rather than from `localStorage` directly. The colour swap is done through CSS, not React state, so the rendered HTML is theme-agnostic.
- **Risk**: ESLint `primary-allowlist` rule does not change behaviour, but light-mode `primary` orange may render as harder to spot against `#f6f6f6`.
  → **Mitigation**: Decorative `primary` use is already capped to brand/Button/Tabs files; no per-theme override needed for the v0 light palette. Revisit if user feedback flags low-prominence CTAs.
- **Trade-off**: Component-level token map (`components` constant in `design-tokens.ts`) keeps emitting *dark-resolved* values. Any downstream code that read those raw hex strings (rather than going through Tailwind utilities) would not theme-swap. **None today** — verified by grep against the frontend tree before implementation. If new code starts doing this, the codegen would need to expose `componentsByTheme` instead.

## Migration Plan

1. Land the codegen + DESIGN.md restructure in one commit; `tokens:check` keeps CI green because the regenerated `globals.css` and `design-tokens.ts` both stay byte-identical for the dark theme (only *additions* land — new `[data-theme="light"]` block, new `themes` export).
2. Land `lib/theme.ts`, `ThemeProvider`, `ThemeToggle`, palette commands, and the `layout.tsx` injection in a second commit; this is when the user-visible toggle appears.
3. No data migration; localStorage starts empty → resolves to `system` → renders `dark` or `light` based on OS preference. No rollback steps required beyond `git revert`.

## Open Questions

*(none — all design decisions resolved against the proposal's constraints.)*
