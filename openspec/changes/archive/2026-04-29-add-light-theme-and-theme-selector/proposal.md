## Why

The dashboard at `frontend/` ships only the dark "OSINT terminal" palette baked into a single `:root` block in `globals.css`. Operators working in bright environments (sunlit desks, projectors during incident reviews, accessibility needs) have no light alternative, and the system-preference signal is ignored entirely. Both the design system and the codegen pipeline are token-driven, so adding a second palette is cheap *now* — every additional component shipped against a single-theme assumption raises the future migration cost.

## What Changes

- Restructure `/DESIGN.md`'s flat `colors:` block into a `themes:` map with `themes.dark` (current 18 tokens, verbatim) and `themes.light` (new palette, WCAG-AA compliant for body text).
- Update `frontend/scripts/generate-design-tokens.ts` to emit dual blocks in `globals.css` — `:root` (dark, default) and `[data-theme="light"]` overriding only the colour custom properties — and to expose a typed `themes` constant in `design-tokens.ts`. The existing flat `colors` export keeps emitting `themes.dark` so Tailwind config and components compile unchanged.
- Add `frontend/lib/theme.ts` with the pure `resolveTheme(stored, systemPrefersDark)` helper used by both the FOUC pre-hydration script and the React provider.
- Add `frontend/components/providers/ThemeProvider.tsx` (context + `matchMedia('(prefers-color-scheme: dark)')` listener active only when mode is `system`) and a `ThemeToggle` segmented control rendered in `TopNav`.
- Inject a synchronous pre-hydration script in `app/layout.tsx`'s `<head>` that reads `localStorage['bns:theme']` (or system preference) and sets `document.documentElement.dataset.theme` before React hydrates — eliminates the flash of wrong theme.
- Register three NAV-kind palette commands in `lib/commands.ts`: `theme: dark`, `theme: light`, `theme: system`, sharing the toggle's setter via the existing `ExplorerCommandsContext` pattern.
- Update `CLAUDE.md`'s Architecture section to document the `data-theme` attribute on `<html>` and the `bns:theme` localStorage key.

## Capabilities

### New Capabilities
*(none)*

### Modified Capabilities
- `web-dashboard`: adds requirements for theme management — three-mode selector (dark/light/system), persistence, system-preference reactivity, and FOUC mitigation.

## Impact

- **Affected code**: `/DESIGN.md`, `frontend/scripts/generate-design-tokens.ts`, `frontend/app/globals.css` (regenerated), `frontend/lib/design-tokens.ts` (regenerated), `frontend/app/layout.tsx`, `frontend/components/topnav/`, `frontend/lib/commands.ts`, plus new `frontend/lib/theme.ts`, `frontend/components/providers/ThemeProvider.tsx`, `frontend/components/topnav/ThemeToggle.tsx`. New vitest suites: `lib/__tests__/theme.test.ts`, `components/__tests__/theme-toggle.test.tsx`, codegen dual-block assertion in the existing scripts test surface.
- **Out of scope**: Tailwind `dark:` variant migration (we deliberately stay on CSS-variable swapping); Playwright visual snapshots for the light palette (the wider visual-regression work is already deferred in `redesign-dashboard-design-system` §4.8 and §11.5); theming the legacy `src/web/static/index.html` (it is being removed in §11.1); per-component palette overrides beyond colour tokens.
- **Public API**: no REST API change. Backend untouched.
- **Dependencies**: no new runtime deps. The codegen script already depends on `js-yaml`.
- **Migration risk**: low. Token *names* are identical across themes, so existing Tailwind utilities and the ESLint allowlists keep working. The `colors` export remains backwards-compatible.
- **Coordination**: lands independently of `redesign-dashboard-design-system` §11 cutover; does not block or get blocked by it.
