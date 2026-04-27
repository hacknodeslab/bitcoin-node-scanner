# Design

Internal design references for `bitcoin-node-scanner`. Source of truth for operator-facing UI — what screens exist, how they behave, why decisions were made.

Not marketing material. Not an exported Figma. Working documents that get forked and edited as the product evolves.

## Contents

| File | What it is |
|------|------------|
| `dashboard-v0.html` | First-pass design reference for the operator dashboard: design tokens, explorer view, command palette, node detail drawer, and open questions. |

## Viewing

Open any `.html` file in a browser. Self-contained, no build step. Only external dependency is JetBrains Mono from Google Fonts — falls back cleanly to system monospace when offline.

## When to update

Update the design refs **before** implementation starts, not after. Treat them as spec.

Update — or add a new file — when:

- A new top-level screen is introduced (map tab, billing page, alert config view).
- A shared component changes meaningfully (table density, new pill vocabulary, query-bar grammar).
- Design tokens change (new color, new type size, new spacing unit).
- An "Open Question" is resolved — update the doc and remove the question.

Small in-flight tweaks (copy, padding, a new filter option) don't need a new version. Edit in place and note the change in the PR description.

## Versioning

A new major design direction = a new file: `dashboard-v1.html`, `dashboard-v2.html`. Keep the old ones in-repo — they're the evidence trail of why decisions were made.

## Design principles

Five rules that should survive any redesign:

1. **Monospace everywhere.** Hierarchy comes from size and weight, never from switching type family.
2. **Color encodes state, not decoration.** Orange is brand only. Red = actionable finding. Amber = warn / tor. Green = healthy / live.
3. **Data density over whitespace.** This is an operator tool, not a landing page. Dense tables beat heroes.
4. **L402 is a first-class action.** Pay-to-unlock is a feature, not a paywall. Always visible, never intrusive.
5. **The palette is the API.** Every command has a matching CLI flag and REST endpoint with the same grammar.

## Open questions

See section 04 of `dashboard-v0.html` for design decisions that are still open. Resolve a question by editing the doc directly — update the relevant view, remove the question from section 04, note the change in the PR.

## Contributing

Changes go through PRs like any other code. Tag `@ifuensan` for design review.

---

HackNodes Lab · Valencia · 2026
