---
version: alpha
name: bns / scanner
description: Operator dashboard for bitcoin-node-scanner. OSINT terminal aesthetic — data-dense, monospace-first, Bitcoin orange reserved for brand and CTAs.

themes:
  dark:
    primary: "#F7931A"
    bg: "#0a0a0a"
    surface: "#141414"
    surface-2: "#1a1a1a"
    border: "#2a2a2a"
    border-dim: "#1e1e1e"
    text: "#e0e0e0"
    text-dim: "#aaaaaa"
    muted: "#888888"
    dim: "#555555"
    ok: "#00ff9c"
    warn: "#ffb000"
    alert: "#ff4444"
    accent: "#ff6fb5"
    on-primary: "#0a0a0a"
    alert-bg: "#2a0000"
    warn-bg: "#2a1f00"
    ok-bg: "#002a1a"
    l402-bg: "#1a1200"
    accent-bg: "#2a0a1a"
    accent-border: "#5a1a3a"
  light:
    primary: "#F7931A"
    bg: "#f6f6f6"
    surface: "#ffffff"
    surface-2: "#ececec"
    border: "#d4d4d4"
    border-dim: "#e4e4e4"
    text: "#1a1a1a"
    text-dim: "#404040"
    muted: "#5a5a5a"
    dim: "#8a8a8a"
    ok: "#008f5c"
    warn: "#a36a00"
    alert: "#cc0000"
    accent: "#a01055"
    on-primary: "#0a0a0a"
    alert-bg: "#ffe5e5"
    warn-bg: "#fff4d6"
    ok-bg: "#daf5e8"
    l402-bg: "#fff2d6"
    accent-bg: "#ffe3f0"
    accent-border: "#e090b8"

typography:
  display:
    fontFamily: JetBrains Mono
    fontSize: 22px
    fontWeight: 500
    lineHeight: 1.3
  title:
    fontFamily: JetBrains Mono
    fontSize: 17px
    fontWeight: 500
    lineHeight: 1.4
  body:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.55
  body-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
  meta:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: 400
  label:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: 500
    letterSpacing: 0.6px
  mono-num:
    fontFamily: JetBrains Mono
    fontSize: 16px
    fontWeight: 500

rounded:
  none: 0px

spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px

components:
  pill-alert:
    backgroundColor: "{themes.dark.alert-bg}"
    textColor: "{themes.dark.alert}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: 2px

  pill-warn:
    backgroundColor: "{themes.dark.warn-bg}"
    textColor: "{themes.dark.warn}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: 2px

  pill-ok:
    backgroundColor: "{themes.dark.ok-bg}"
    textColor: "{themes.dark.ok}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: 2px

  button-secondary:
    backgroundColor: "{themes.dark.surface-2}"
    textColor: "{themes.dark.text-dim}"
    typography: "{typography.meta}"
    rounded: "{rounded.none}"
    padding: 4px

  button-secondary-hover:
    backgroundColor: "{themes.dark.surface-2}"
    textColor: "{themes.dark.text}"

  button-l402:
    backgroundColor: "{themes.dark.l402-bg}"
    textColor: "{themes.dark.primary}"
    typography: "{typography.meta}"
    rounded: "{rounded.none}"
    padding: 5px

  input-query:
    backgroundColor: "{themes.dark.bg}"
    textColor: "{themes.dark.text}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.none}"
    padding: 10px

  card:
    backgroundColor: "{themes.dark.surface}"
    rounded: "{rounded.none}"
    padding: 8px

  table-row:
    backgroundColor: "{themes.dark.bg}"
    textColor: "{themes.dark.text}"
    typography: "{typography.body-sm}"
    padding: 9px

  table-row-expanded:
    backgroundColor: "{themes.dark.surface}"
    textColor: "{themes.dark.text}"

  stat-tile:
    backgroundColor: "{themes.dark.bg}"
    textColor: "{themes.dark.text}"
    typography: "{typography.mono-num}"
    rounded: "{rounded.none}"
    padding: 10px

  command-palette-item:
    backgroundColor: "{themes.dark.bg}"
    textColor: "{themes.dark.text}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.none}"
    padding: 7px

  command-palette-item-focused:
    backgroundColor: "{themes.dark.surface}"
    textColor: "{themes.dark.text}"
---

## Overview

OSINT terminal. The dashboard is a working surface for security operators investigating the Bitcoin peer-to-peer network — exposed RPCs, vulnerable Tor nodes, stale Bitcoin Core versions. It sits visually between Shodan, `bitnodes.io`, and the output of an `nmap` scan rendered in a developer's terminal.

The aesthetic communicates *technical seriousness*. Operators are skeptical of glossy SaaS. Polish here looks like discipline, not decoration: every pixel earns its place, every color encodes meaning, and density is a feature.

Two non-negotiable rules govern this system:

1. **Color encodes state, not decoration.** A red badge means an actionable security finding. Bitcoin orange means brand or premium CTA. There is no decorative use of color anywhere.
2. **Monospace everywhere.** A single typeface (JetBrains Mono) carries every word in the product. Hierarchy is built from size, weight, and color — never from switching families.

## Colors

The system ships **two palettes** — a default dark and an opt-in light — both built around the same 18 token names. Operators choose their mode (dark / light / system) from a TopNav toggle; the choice persists in `localStorage['bns:theme']`. The dark palette is the canonical "OSINT terminal" surface; the light palette is its high-contrast daylight twin and meets WCAG AA (≥ 4.5:1) for body text.

Token names are theme-agnostic — every component references `bg`, `surface`, `text`, `alert`, etc. without knowing which palette is active. At runtime, `<html data-theme="light">` swaps the CSS custom properties; the absence of that attribute (or `data-theme="dark"`) renders the dark palette.

The palette is built on a near-black canvas in dark mode (pure black `#000000` bands on OLED; `#0a0a0a` reads as black without artifacts) and on a near-white canvas in light mode (`#f6f6f6` keeps body text from sitting on a glaring `#ffffff` page).

- **Primary `#F7931A`** — Bitcoin orange. Used for the brand mark, focused tab indicators, and the L402 pay-to-unlock CTA. **Identical on both themes** — the brand mark must read as the brand mark in either light or dark. Never used as filler. If a screen has Bitcoin orange in three places, two are wrong.
- **Background** — `#0a0a0a` (dark) / `#f6f6f6` (light). The canvas.
- **Surface** — `#141414` (dark) / `#ffffff` (light). Cards, inputs, expanded table rows. Always sits above the canvas with a 1px `border` divider.
- **Border** — `#2a2a2a` (dark) / `#d4d4d4` (light). All frame dividers and table outlines. `border-dim` (`#1e1e1e` / `#e4e4e4`) is used inside cards for internal separators when the contrast of `border` would compete with content.
- **Text** — `#e0e0e0` (dark) / `#1a1a1a` (light). Primary text. In dark mode, pure white (`#ffffff`) is too harsh against the canvas; `#e0e0e0` keeps a soft luminance for long sessions. In light mode, near-black on near-white preserves comparable readability while staying off pure `#000`.
- **Text dim, muted, dim** — A descending ladder for hierarchy *within* text. `text-dim` (`#aaaaaa` / `#404040`) for secondary information, `muted` (`#888888` / `#5a5a5a`) for metadata, `dim` (`#555555` / `#8a8a8a`) for separators (`·`), placeholder hints, and quiet UI affordances (chevrons).
- **Alert** — `#ff4444` (dark) / `#cc0000` (light). Always means "actionable security finding". Exposed RPC, stale Core version, CVE present. Paired with `alert-bg` (`#2a0000` / `#ffe5e5`) for pill backgrounds.
- **Warn** — `#ffb000` (dark) / `#a36a00` (light). Tor / onion nodes (informational, not a risk) and CVEs of medium severity in co-located services. Paired with `warn-bg` (`#2a1f00` / `#fff4d6`).
- **Ok** — `#00ff9c` (dark) / `#008f5c` (light). "Live" indicators (active scan tick) and "no findings" status. Paired with `ok-bg` (`#002a1a` / `#daf5e8`). The dark green is bright terminal-style; the light green is darkened for adequate contrast against a white surface.

The only color allowed to overlap meanings is `dim`, which carries multiple "quiet" roles. Every other color has a single semantic job, in either theme.

## Typography

A single family, **JetBrains Mono**, in three weights: 400 (body), 500 (titles, emphasis, numbers), 600 (rarely — only when 500 is insufficient against the canvas).

Hierarchy is built from three levers: **size**, **weight**, and **color**. The label style (`label`) uses `+0.6px` letter-spacing and uppercased text in copy to create section headers without needing a heavier weight.

| Token | Use |
|---|---|
| `display` 22/500 | Hero/marketing surfaces only. Not present in the dashboard. |
| `title` 17/500 | Section headers, drawer addresses. |
| `body` 13/400 | Default reading size. Long-form prose. |
| `body-sm` 12/400 | Default for the dashboard — table rows, command palette, cards. The dashboard is a dense view, so its baseline is one step smaller than typical web body. |
| `meta` 11/400 | Subheaders, timestamps, secondary labels. |
| `label` 10/500 +0.6 LS | Section labels (`OPEN PORTS`, `EXPOSURE FINDINGS`). Always uppercase in the rendered text. |
| `mono-num` 16/500 | Stat-tile numbers — the figures that headline KPIs. |

Numerical content (IPs, ports, versions, ASNs, sat amounts) inherits the body family naturally because everything is monospace; vertical alignment in tables comes for free.

## Layout

The dashboard is built on a strict 8px grid. Spacing tokens (`xs 4`, `sm 8`, `md 12`, `lg 16`, `xl 24`) cover virtually all gaps. Padding inside cards and table rows uses `sm`/`md`; gaps between top-level sections use `lg`/`xl`.

The dashboard layout is a vertical stack of horizontal bars: top nav → query bar → stats strip → table → footer. No multi-column layouts on the main view — operators want a single linear path through the information. Multi-column appears only inside the node detail drawer (sliver + main panel).

Table rows are dense by design: 9px vertical padding. This is below typical web conventions because operators are scanning, not reading. When a row is expanded inline, it gets a 2px left border in the relevant state color (`alert` for exposure findings) to anchor the operator's eye to the expanded content.

Maximum content width on read-heavy views: 960px. The dashboard itself is full-width — operators run it on wide monitors.

## Elevation & Depth

There is no elevation. No drop shadows, no glows, no glassmorphism, no blurs.

Surfaces are distinguished by **flat color steps and 1px borders**, never by light. The hierarchy is `bg → surface → surface-2`, each separated by a 1px `border` line. In dark mode this reads `#0a0a0a → #141414 → #1a1a1a`; in light mode it inverts to `#f6f6f6 → #ffffff → #ececec`. This is deliberate: shadows and glows are the visual language of consumer SaaS. The absence of them is part of why this product looks like a tool.

The only exception is the command palette, which sits over a translucent backdrop (`rgba(0,0,0,0.5)`) when open. This is functional dimming of the underlying view, not elevation.

## Shapes

**Sharp corners only.** All `rounded` tokens resolve to `0px`. This is intentional: rounded corners read as friendly, sharp corners read as engineered. The product's tone leans hard into the second.

All borders are 1px solid. No double borders, no inset/outset effects, no dashed lines except inside `notes` callouts in design references where dashed dividers communicate "non-structural separator".

Pills are rectangular with 2px vertical / 7px horizontal padding. They never round.

## Components

### Pills (status badges)

Three semantic variants — `pill-alert`, `pill-warn`, `pill-ok`. They are the most repeated component in the system and the primary at-a-glance signal in tables. Each uses its color paired with a darkened `*-bg` background for readability without being loud.

Pills carry one of the controlled vocabulary words: `EXPOSED`, `STALE`, `TOR`, `CVE`, `OK`. Custom strings inside pills are not allowed — adding a new pill word is a design system change, not a feature flag.

### Buttons

- **`button-secondary`** — the default. Used for row actions, drawer footers, palette commands. Hover state changes only the text color (to full `text`), never the background. No primary button exists in the dashboard surface — there is rarely "the action" to take, only menus of actions.
- **`button-l402`** — the only "loud" button. Reserved for paying with Lightning to unlock content. Distinct background (`l402-bg`), Bitcoin orange border and text, lightning glyph (`⚡`) prefix. Always positioned at the right end of an action row, never in the middle.

### Card

Flat surface for grouping related data (open ports, vulnerabilities, cross-references). 1px `border-dim` outline, no rounding, no shadow. Rows inside a card are separated by 1px `border-dim` horizontal dividers.

### Table row

The workhorse. 9px vertical padding, 14px horizontal. Grid column layout for tabular data. Hover state is implicit (no background change on hover); selection state uses a 2px left border in `primary`.

### Table row expanded

When a row expands inline, it switches to `surface` background and gains a 2px left border in the state color of the row (e.g., `alert` for an exposed-RPC row). The expanded body uses 32px left padding to indent findings beneath the row's chevron column.

### Stat tile

5-column or 4-column strip at the top of the explorer. Each tile shows a `label` header and a `mono-num` value, optionally with a delta. Deltas use `ok` for positive movement, `alert` for negative movement, and the meaning of "positive" depends on the metric (a rising "EXPOSED" count is bad — it gets `alert` red, not `ok` green).

### Command palette item

11/400 height (consistent with `meta`), focused state gains the 2px left border in `primary` and a `surface` background. Multiple-line items are forbidden — every command must fit in one line at standard breakpoints.

## Do's and Don'ts

**Do** treat color as semantic. If you reach for a color, ask which of the four accent meanings it represents (brand, ok, warn, alert). If it's none of them, use a gray.

**Do** lead with data. Every screen should show real values within 200ms of opening. Empty states are the only acceptable exception, and they should be one short line of text, not an illustration.

**Do** keep tables dense. Operators came here to work, not to admire whitespace. 9px row padding is the floor; don't add air to "make it breathe."

**Do** treat L402 as a feature. Pay-to-unlock affordances should be visible and well-formed wherever there's premium content — never hidden behind a menu, never disguised as something else.

**Do** keep the command palette and the API in lockstep. Every entry in the palette must have a matching CLI flag and REST endpoint with consistent grammar. The palette *is* the product's surface for the API.

**Don't** add gradients, glows, blurs, drop shadows, or glassmorphism. Anywhere. They erase the system's identity.

**Don't** introduce a second typeface. Not for headings, not for "personality", not for code blocks (it's already monospace). One family.

**Don't** use Bitcoin orange as filler. If the brand color appears in more than three places on a single screen, at least two are wrong. Reserve it for the logo, focused tab indicators, and L402 affordances.

**Don't** round corners. Ever. Not on cards, not on buttons, not on inputs, not on pills.

**Don't** invent new pill labels in code. Pills carry a controlled vocabulary (`EXPOSED`, `STALE`, `TOR`, `CVE`, `OK`). New states are a design system change with rationale, not an inline string literal.

**Don't** soften messaging. The product is for people whose job is to find things that are broken. "3 nodes have issues" is wrong; "3 EXPOSED" is right.

**Don't** decorate with icons. The system uses a minimal set of glyphs (`›`, `⌄`, `●`, `⚡`, `⌕`, `✗`, `⚠`, `·`, `⌘`) drawn from Unicode and keyboard symbols. No icon library. No logos in tables. No emoji.

## References

Companion documents that ground this spec in concrete UI:

- **`docs/design/dashboard-v0.html`** — visual spec showing how the tokens above compose into the three core views (explorer, command palette, node detail drawer). Open in a browser to see real renderings of every component defined here. When a token in this file changes, that HTML must be updated to match.
- **`docs/design/README.md`** — workflow notes on how the design folder is maintained, when to version, and how unresolved decisions are tracked.

Agents implementing this design system should treat `DESIGN.md` as the source of truth for token values and rationale, and `docs/design/dashboard-v0.html` as the source of truth for layout, density, and component composition.
