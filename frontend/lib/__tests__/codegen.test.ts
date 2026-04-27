/**
 * Token codegen output: assert globals.css ships both the dark `:root` block
 * (default fallback) and the `[data-theme="light"]` override with the exact
 * light-palette values frozen in design.md D3, plus that design-tokens.ts
 * exposes a `themes` constant where `themes.dark === colors`.
 *
 * If this test fails after a DESIGN.md edit, run `pnpm tokens:gen` and commit.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { themes, colors } from "../design-tokens";

const FRONTEND_ROOT = resolve(__dirname, "..", "..");
const GLOBALS_CSS = readFileSync(
  resolve(FRONTEND_ROOT, "app", "globals.css"),
  "utf8",
);

describe("globals.css generated tokens", () => {
  it("contains a :root block (dark default)", () => {
    expect(GLOBALS_CSS).toMatch(/:root\s*\{[^}]*--color-bg:\s*#0a0a0a/);
    expect(GLOBALS_CSS).toMatch(/:root\s*\{[^}]*--color-text:\s*#e0e0e0/);
  });

  it('contains a [data-theme="light"] block with the frozen palette', () => {
    const m = GLOBALS_CSS.match(
      /\[data-theme="light"\]\s*\{([\s\S]*?)\}/,
    );
    expect(m, "globals.css missing the light-theme block").toBeTruthy();
    const block = m![1];
    const expected: Record<string, string> = {
      primary: "#F7931A",
      bg: "#f6f6f6",
      surface: "#ffffff",
      "surface-2": "#ececec",
      border: "#d4d4d4",
      "border-dim": "#e4e4e4",
      text: "#1a1a1a",
      "text-dim": "#404040",
      muted: "#5a5a5a",
      dim: "#8a8a8a",
      ok: "#008f5c",
      warn: "#a36a00",
      alert: "#cc0000",
      "on-primary": "#0a0a0a",
      "alert-bg": "#ffe5e5",
      "warn-bg": "#fff4d6",
      "ok-bg": "#daf5e8",
      "l402-bg": "#fff2d6",
    };
    for (const [name, hex] of Object.entries(expected)) {
      expect(block).toContain(`--color-${name}: ${hex}`);
    }
  });

  it("the light block does not include spacing/font tokens (those stay on :root only)", () => {
    const m = GLOBALS_CSS.match(/\[data-theme="light"\]\s*\{([\s\S]*?)\}/);
    const block = m![1];
    expect(block).not.toMatch(/--space-/);
    expect(block).not.toMatch(/--font-/);
    expect(block).not.toMatch(/--rounded-/);
  });
});

describe("design-tokens.ts themes export", () => {
  it("themes.dark deep-equals the colors export", () => {
    expect(themes.dark).toEqual(colors);
  });

  it("themes.light has the WCAG-AA values from design.md D3", () => {
    expect(themes.light.bg).toBe("#f6f6f6");
    expect(themes.light.text).toBe("#1a1a1a");
    expect(themes.light.primary).toBe("#F7931A");
    expect(themes.light["on-primary"]).toBe("#0a0a0a");
    expect(themes.light.alert).toBe("#cc0000");
    expect(themes.light.ok).toBe("#008f5c");
    expect(themes.light.warn).toBe("#a36a00");
  });
});
