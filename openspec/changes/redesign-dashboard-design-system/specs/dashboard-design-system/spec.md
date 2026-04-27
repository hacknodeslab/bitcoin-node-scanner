## ADDED Requirements

### Requirement: `/DESIGN.md` is the binding token contract
The dashboard codebase SHALL treat `/DESIGN.md` as the single source of truth for design tokens (colours, typography, spacing, component variants). Tokens declared in the YAML front matter SHALL be the only values rendered as colour, font family, font size, font weight, line height, letter spacing, spacing, or component padding in the dashboard. Any conflict between `/DESIGN.md` and a third-party library's defaults (including shadcn/ui) SHALL be resolved in favour of `/DESIGN.md`.

#### Scenario: Adding an arbitrary colour fails CI
- **WHEN** a developer adds `className="text-[#cc00cc]"` or `style={{ color: '#cc00cc' }}` in a dashboard component
- **THEN** the lint stage of CI SHALL fail with a message identifying the file, line, and the rule that requires colours to come from `/DESIGN.md`

#### Scenario: shadcn default overridden
- **WHEN** a shadcn component is added that ships with a non-token colour or `border-radius` greater than 0
- **THEN** the same lint stage SHALL fail until the component is overridden to use design tokens and `rounded-none`

### Requirement: Tokens are codegen'd from `/DESIGN.md` into TypeScript
The build SHALL parse the YAML front matter of `/DESIGN.md` and emit a TypeScript module (e.g. `frontend/lib/design-tokens.ts`) exporting the tokens as typed constants. The Tailwind configuration SHALL import its `theme.extend.colors`, `theme.extend.fontFamily`, `theme.extend.fontSize`, `theme.extend.spacing`, and `theme.extend.borderRadius` from this module.

#### Scenario: Stale generated tokens fail CI
- **WHEN** `/DESIGN.md` is edited but the generated `design-tokens.ts` is not regenerated
- **THEN** the CI step that re-runs the codegen and diffs the result SHALL fail and block the merge

#### Scenario: Tailwind exposes only token-derived utilities
- **WHEN** a developer writes `bg-alert` in a component
- **THEN** Tailwind SHALL emit the colour value defined under `colors.alert` in `/DESIGN.md` (`#ff4444`); writing `bg-redx` SHALL fail at build time because no such token exists

### Requirement: CSS custom properties mirror tokens on `:root`
A `globals.css` `@layer base` block SHALL emit each token from `/DESIGN.md` as a CSS custom property on `:root` (e.g. `--color-alert: #ff4444`). Code paths that cannot use Tailwind utilities (Radix data-attribute styling, embedded SVGs, third-party widgets) SHALL read tokens via these custom properties and SHALL NOT hardcode hex values.

#### Scenario: Embedded SVG icon uses var
- **WHEN** an inline SVG glyph needs the alert colour
- **THEN** its `fill` attribute SHALL reference `var(--color-alert)`, not `#ff4444`

### Requirement: JetBrains Mono is the only typeface
The dashboard SHALL load JetBrains Mono via `next/font/google` and SHALL set it as the default `font-family` on `<html>` (or `<body>`). No other font (Inter, system serifs, additional Google Fonts) SHALL be imported anywhere in the frontend codebase.

#### Scenario: Inter import is rejected
- **WHEN** a developer adds `import { Inter } from 'next/font/google'` in any frontend file
- **THEN** the lint stage SHALL fail with a message naming the rule that bans non-JetBrains-Mono fonts

#### Scenario: Default font is JetBrains Mono
- **WHEN** the dashboard is rendered
- **THEN** the computed `font-family` of every text node SHALL resolve to JetBrains Mono with a monospace fallback chain (`ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`)

### Requirement: All `rounded-*` resolve to `rounded-none`
Every component, primitive, and override in the dashboard SHALL render with `border-radius: 0`. The Tailwind theme SHALL define only `rounded-none`. Direct CSS `border-radius` values greater than 0 SHALL NOT appear in the codebase.

#### Scenario: Rounded utility is rejected
- **WHEN** a developer writes `className="rounded-md"` or `className="rounded-full"` in any component
- **THEN** the lint stage SHALL fail and the rule message SHALL link to the relevant section of `/DESIGN.md`

### Requirement: No shadows, gradients, blurs, or backdrop filters
Drop shadows, glows, gradients, CSS blurs, and `backdrop-filter` SHALL NOT appear anywhere in the dashboard. The single allowed translucent surface is the command palette backdrop, which SHALL be a flat `rgba(0,0,0,0.5)` colour and SHALL NOT use `backdrop-blur` or `backdrop-filter`.

#### Scenario: Shadow utility is rejected
- **WHEN** a developer writes `className="shadow-sm"` or `style={{ boxShadow: '...' }}`
- **THEN** the lint stage SHALL fail

#### Scenario: Gradient utility is rejected
- **WHEN** a developer writes `className="bg-gradient-to-r"` or any other `bg-gradient-*` utility
- **THEN** the lint stage SHALL fail

#### Scenario: Backdrop filter is rejected
- **WHEN** a developer writes `className="backdrop-blur-sm"` anywhere, including the palette backdrop
- **THEN** the lint stage SHALL fail

### Requirement: Colour is semantic, never decorative
Each rendered colour SHALL have a single semantic role defined in `/DESIGN.md`. Bitcoin orange (`primary`) SHALL be reserved for the brand mark, focused tab indicators, and the L402 button. The lint stage SHALL flag uses of `primary` outside an allow-list of files (`frontend/components/brand/**`, the `l402` variant of `Button`, the `Tabs` focused indicator).

#### Scenario: Decorative orange is rejected
- **WHEN** a developer applies `text-primary` or `bg-primary` in a component outside the allow-list
- **THEN** the lint stage SHALL fail and the message SHALL state the allow-list

#### Scenario: Three or more orange touchpoints in one screen
- **WHEN** a screen renders four or more elements styled with `primary` simultaneously
- **THEN** a runtime visual regression test SHALL fail in CI

### Requirement: Pills carry a controlled vocabulary as a discriminated union
The `Pill` component's `kind` prop SHALL be a TypeScript discriminated union over the values `'EXPOSED'`, `'STALE'`, `'TOR'`, `'CVE'`, `'OK'`. The `'CVE'` variant SHALL carry an additional `severity` field with values `'low' | 'medium' | 'high' | 'critical'`. The component SHALL NOT accept arbitrary strings.

#### Scenario: Adding a new pill word fails type-check
- **WHEN** a developer writes `<Pill kind="WHATEVER" />`
- **THEN** `tsc` SHALL fail with a type error and the lint stage SHALL fail in CI

#### Scenario: Pill colour is fixed by kind
- **WHEN** a `<Pill kind="EXPOSED" />` is rendered
- **THEN** it SHALL apply `text-alert` and `bg-alert-bg` from the token module, with `padding: 2px 7px` and no rounding

#### Scenario: CVE severity drives colour
- **WHEN** a `<Pill kind="CVE" severity="critical" />` is rendered
- **THEN** it SHALL apply `text-alert` and `bg-alert-bg`; for `severity="medium"` it SHALL apply `text-warn` and `bg-warn-bg`

### Requirement: Glyphs replace icon libraries
The dashboard SHALL NOT import from `lucide-react`, `@heroicons/*`, `react-icons`, or any other icon library. Iconography SHALL come from the Unicode glyph allow-list defined in `/DESIGN.md`: `›`, `⌄`, `●`, `⚡`, `⌕`, `✗`, `⚠`, `·`, `⌘`. A `Glyph` component SHALL expose these via a string-literal `name` prop.

#### Scenario: Icon library import is rejected
- **WHEN** a developer writes `import { ChevronRight } from 'lucide-react'`
- **THEN** the lint stage SHALL fail and the message SHALL point to the `Glyph` component

#### Scenario: Glyph name outside allow-list fails type-check
- **WHEN** a developer writes `<Glyph name="rocket" />`
- **THEN** `tsc` SHALL fail because `'rocket'` is not in the literal union of valid names

### Requirement: Dashboard typography uses the token scale
Every text element in the dashboard SHALL use one of the typography tokens defined in `/DESIGN.md` (`display`, `title`, `body`, `body-sm`, `meta`, `label`, `mono-num`). Arbitrary `font-size`, `font-weight`, `line-height`, or `letter-spacing` values SHALL NOT be applied via `style` or arbitrary Tailwind values (`text-[15px]`).

#### Scenario: Default reading size is body-sm
- **WHEN** a node table row renders text without an explicit typography class
- **THEN** the rendered text SHALL match the `body-sm` token (12px / 400 / 1.5 line-height) inherited from the surrounding container

#### Scenario: Arbitrary font-size is rejected
- **WHEN** a developer writes `className="text-[19px]"`
- **THEN** the lint stage SHALL fail
