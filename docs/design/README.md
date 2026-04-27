# Design

Internal design references for `bitcoin-node-scanner`. This folder contains the **visual spec** — concrete renderings of the system in operation.

For canonical token values, naming, and design rationale, see [`/DESIGN.md`](../../DESIGN.md) at the repository root. That file is the machine-readable source of truth and is what coding agents read first.

## How the two pieces fit together

| File | Role | Audience |
|------|------|----------|
| `/DESIGN.md` (root) | Tokens (YAML) + rationale (prose). Source of truth for values and naming. | Coding agents, developers implementing components. |
| `docs/design/dashboard-v0.html` | Visual spec. Shows how the tokens compose into real screens. | Humans reviewing the design, designers iterating on it. |

The two must stay in sync. If a token changes in `DESIGN.md`, the HTML must reflect it. If a component layout changes in the HTML and introduces new tokens, they must be added to `DESIGN.md`.

## Contents

| File | What it is |
|------|------------|
| `dashboard-v0.html` | First-pass visual spec for the operator dashboard: tokens demo, explorer view, command palette, node detail drawer, and open questions. |

## Viewing

Open any `.html` file in a browser. Self-contained, no build step. Only external dependency is JetBrains Mono from Google Fonts — falls back cleanly to system monospace when offline.

## When to update

Update before implementation starts, not after. Treat the HTML as spec.

Update — or add a new file — when:

- A new top-level screen is introduced (map tab, billing page, alert config view).
- A shared component changes meaningfully (table density, new pill vocabulary, query-bar grammar).
- Design tokens change in `/DESIGN.md` — reflect the change visually here too.
- An "Open Question" is resolved — update the doc and remove the question.

Small in-flight tweaks (copy, padding, a new filter option) don't need a new version. Edit in place and note the change in the PR description.

## Versioning

A new major design direction = a new file: `dashboard-v1.html`, `dashboard-v2.html`. Keep the old ones in-repo — they're the evidence trail of why decisions were made.

## Design principles

The five rules that should survive any redesign are documented in `/DESIGN.md` under the Overview and Do's and Don'ts sections. Implementation details and component-level reasoning live there; this folder shows what they look like applied.

## Open questions

See section 04 of `dashboard-v0.html` for design decisions that are still open. Resolve a question by editing the doc directly — update the relevant view, remove the question from section 04, note the change in the PR.

## Contributing

Changes go through PRs like any other code. Tag `@ifuensan` for design review.

---

HackNodes Lab · Valencia · 2026
