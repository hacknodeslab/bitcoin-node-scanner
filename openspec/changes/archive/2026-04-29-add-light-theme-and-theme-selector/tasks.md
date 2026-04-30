## 1. DESIGN.md restructure

- [x] 1.1 Replace the flat `colors:` block in `/DESIGN.md` with a `themes:` map containing `dark` (current 18 tokens, verbatim) and `light` (the palette frozen in design.md D3)
- [x] 1.2 Update component-token references in `/DESIGN.md` (e.g. `pill-alert.backgroundColor`) from `"{colors.alert-bg}"` to `"{themes.dark.alert-bg}"` so the dark resolution still produces the existing `components` constant
- [x] 1.3 Skim `/DESIGN.md` for any prose mentioning "dark mode" or "single palette" and tighten to mention the dual-theme system

## 2. Token codegen

- [x] 2.1 Update `frontend/scripts/generate-design-tokens.ts` to read `themes.dark` and `themes.light` from the parsed YAML; keep the reference resolver working with the new `themes.<mode>.<token>` path
- [x] 2.2 Emit a new `themes` constant in `frontend/lib/design-tokens.ts` keyed by mode, plus keep emitting `colors` as an alias for `themes.dark`
- [x] 2.3 Update the CSS emitter to write a `:root` block (dark) followed by a `[data-theme="light"]` block (light) inside the existing `BEGIN/END GENERATED TOKENS` markers; only colour custom properties belong in the light block (spacing/rounded/font tokens stay in `:root` only)
- [x] 2.4 Run `pnpm tokens:gen` and commit the regenerated `design-tokens.ts` and `globals.css`
- [x] 2.5 Run `pnpm tokens:check` and confirm CI parity

## 3. Theme runtime helpers

- [x] 3.1 Add `frontend/lib/theme.ts` exporting the union type `ThemeMode = 'dark' | 'light' | 'system'`, the resolved type `ResolvedTheme = 'dark' | 'light'`, and the pure helper `resolveTheme(stored: ThemeMode | null, systemPrefersDark: boolean): ResolvedTheme`
- [x] 3.2 Export `THEME_STORAGE_KEY = 'bns:theme'` and `readStoredTheme()` / `writeStoredTheme(mode)` wrappers around `localStorage` that swallow exceptions and degrade to ephemeral state
- [x] 3.3 Export `THEME_INIT_SCRIPT` as a string constant containing the inline IIFE body (reads `localStorage`, falls back to `matchMedia`, sets `document.documentElement.dataset.theme`); document that this string MUST stay behaviourally identical to `resolveTheme`

## 4. ThemeProvider + FOUC injection

- [x] 4.1 Add `frontend/components/providers/ThemeProvider.tsx`: a client component exposing `{ mode, resolved, setMode }` via context. On mount, hydrate `mode` from `localStorage` (falling back to `'system'`); compute `resolved` via `resolveTheme`; subscribe to `matchMedia('(prefers-color-scheme: dark)')` only while `mode === 'system'`; teardown the listener on transitions
- [x] 4.2 `setMode(next)` SHALL write `localStorage`, recompute `resolved`, and set `document.documentElement.dataset.theme` synchronously (no React state pre-paint dance — the attribute write is the source of truth for CSS)
- [x] 4.3 In `frontend/app/layout.tsx`, inject the FOUC script via `<Script id="theme-init" strategy="beforeInteractive">{THEME_INIT_SCRIPT}</Script>` placed inside `<head>`; remove any pre-existing hard-coded `data-theme` attribute on `<html>`
- [x] 4.4 Wrap the explorer client root in `<ThemeProvider>` so the toggle and palette commands share the same context

## 5. ThemeToggle in TopNav

- [x] 5.1 Add `frontend/components/topnav/ThemeToggle.tsx`: three sibling `button` elements rendered horizontally, each labelled with a `Glyph` from the existing `GLYPHS` map (no new icon library); the active option SHALL receive `border-b border-primary` (matching `Tabs.tsx`'s active treatment)
- [x] 5.2 Mount `ThemeToggle` in the existing `TopNav` between the brand and the ⌘K hint
- [x] 5.3 Add `aria-pressed` (or `role="radiogroup"` + `aria-checked`) so the active state is exposed to assistive tech
- [x] 5.4 Confirm ESLint allowlist passes (`text-primary`, `border-primary` are already allowed in `topnav/`? — if not, extend the allowlist to include `components/topnav/ThemeToggle.tsx`)

## 6. Palette commands

- [x] 6.1 Add three `NAV` entries in `frontend/lib/commands.ts`: `theme-dark`, `theme-light`, `theme-system` with labels `theme: dark`, `theme: light`, `theme: system` and `restEndpoint: null`
- [x] 6.2 Wire the actions through `ExplorerCommandsContext` so palette invocations route into the same `setMode` exposed by `ThemeProvider`
- [x] 6.3 Rerun `lib/__tests__/commands.test.ts` and confirm the three new entries pass the existing NAV/restEndpoint contract

## 7. Tests

- [x] 7.1 `lib/__tests__/theme.test.ts`: cover `resolveTheme` matrix (4 inputs × 2 system states + null stored), `readStoredTheme` returns null on JSON garbage / privacy-mode throw, `writeStoredTheme` returns false on quota exceeded
- [x] 7.2 In the same test file, parse `THEME_INIT_SCRIPT` (treat as a string), evaluate it in a sandboxed `vm`/`Function` against fake `window`/`document`/`localStorage`, and assert behavioural parity with `resolveTheme` over the same input matrix
- [x] 7.3 `components/__tests__/theme-toggle.test.tsx`: render `<ThemeProvider><ThemeToggle/></ThemeProvider>`, assert active option renders the underline, click each option and assert `<html data-theme>` plus `localStorage['bns:theme']` updates
- [x] 7.4 Extend the existing token codegen test (or add a new `scripts/__tests__/codegen.test.ts`) to assert the regenerated `globals.css` contains both a `:root` block and a `[data-theme="light"]` block with the exact light-palette values from spec D3
- [x] 7.5 Add a single integration smoke in `components/__tests__/ui.test.tsx` (or a new file) that mounts a representative card under `data-theme="light"` and asserts no banned utilities slipped in (the existing smoke pass already covers dark)
- [x] 7.6 Run `pnpm test` and confirm the full vitest suite is green

## 8. Documentation

- [x] 8.1 Update `CLAUDE.md`'s Architecture section to document: theme tokens live in `themes.{dark,light}`, the `<html data-theme>` attribute, and the `bns:theme` localStorage key
- [x] 8.2 Update `docs/design/README.md` (if it references the flat `colors:` block) to mention the new `themes:` structure

## 9. Verification

- [x] 9.1 `pnpm --filter frontend lint typecheck build` runs clean
- [x] 9.2 `pnpm --filter frontend test` runs clean
- [x] 9.3 Manual smoke: hard-reload in dark mode, hard-reload in light mode, verify no flash on either; toggle through all three options in TopNav and via the palette; flip OS preference while in `system` mode and confirm the dashboard re-renders live. Smoke uncovered that `tailwind.config.ts` was consuming `colors` (dark hex) literally — utilities never reacted to `data-theme`. Fixed by mapping each colour token to `var(--color-<token>)` in `tailwind.config.ts`
- [x] 9.4 `openspec validate add-light-theme-and-theme-selector --strict` passes with zero errors
