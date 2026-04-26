/**
 * Smoke tests for the owned + kept primitives.
 *
 * Two contracts asserted across the suite:
 *   1. NO element in any rendered tree carries a `rounded-{x}` class other
 *      than `rounded-none` (in practice we never emit one, so we look for
 *      the absence of any `rounded-` prefix that isn't `rounded-none`).
 *   2. NO element carries `shadow-*`, `blur-*`, `backdrop-*`, or
 *      `bg-gradient-*` classes.
 *
 * Computed styles in jsdom don't reflect Tailwind utilities (no PostCSS
 * pipeline runs), so we assert at the className level — the same surface
 * our ESLint rules guard at static-analysis time. This catches both lint
 * regressions and any inline `style` shortcut that bypasses Tailwind.
 */
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";

import { Glyph, GLYPHS } from "../ui/Glyph";
import { Pill } from "../ui/Pill";
import { Button } from "../ui/Button";
import { Card, CardLabel, CardRow } from "../ui/Card";
import { Input } from "../ui/Input";
import { StatTile } from "../ui/StatTile";
import { TableRow, TableExpandedRow } from "../ui/TableRow";
import { QueryBar, parseQuery } from "../ui/QueryBar";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/Tabs";

const FORBIDDEN_CLASS_RE =
  /(?:^|[\s:])(rounded-(?!none\b)[a-z0-9-]+|shadow-[a-z0-9-]+|blur-[a-z0-9-]+|backdrop-[a-z0-9-]+|bg-gradient-[a-z0-9-]+)(?:$|\s)/;

function assertNoForbiddenClasses(container: HTMLElement) {
  // Walk every element including the container itself.
  const all = [container, ...Array.from(container.querySelectorAll("*"))];
  for (const el of all) {
    const cls = el.getAttribute("class") ?? "";
    if (FORBIDDEN_CLASS_RE.test(cls)) {
      throw new Error(
        `Forbidden Tailwind utility on <${el.tagName.toLowerCase()}>: ${cls}`,
      );
    }
    // Also catch inline style border-radius / box-shadow / filter overrides.
    const style = el.getAttribute("style") ?? "";
    if (/border-radius\s*:/.test(style) && !/border-radius\s*:\s*0/.test(style)) {
      throw new Error(`Inline non-zero border-radius on <${el.tagName.toLowerCase()}>: ${style}`);
    }
    if (/box-shadow\s*:/.test(style) || /filter\s*:\s*blur/.test(style) || /backdrop-filter/.test(style)) {
      throw new Error(`Inline shadow/blur/backdrop on <${el.tagName.toLowerCase()}>: ${style}`);
    }
  }
}

describe("/DESIGN.md hard rules — class-level smoke", () => {
  it.each([
    ["Glyph", <Glyph key="g" name="chevron" />],
    ["Pill EXPOSED", <Pill key="p1" kind="EXPOSED" />],
    ["Pill TOR", <Pill key="p2" kind="TOR" />],
    ["Pill CVE critical", <Pill key="p3" kind="CVE" severity="critical" />],
    ["Pill CVE medium", <Pill key="p4" kind="CVE" severity="medium" />],
    ["Pill OK", <Pill key="p5" kind="OK" />],
    ["Button secondary", <Button key="b1">cancel</Button>],
    ["Button l402", <Button key="b2" variant="l402">unlock</Button>],
    ["Card", <Card key="c1"><CardLabel>OPEN PORTS</CardLabel><CardRow>row</CardRow></Card>],
    ["Input", <Input key="i1" placeholder="x" />],
    ["StatTile", <StatTile key="s1" label="EXPOSED" value={42} delta={{ value: "+3", direction: "rising-bad" }} />],
    ["TableRow selected", <TableRow key="r1" selected>row</TableRow>],
    ["TableExpandedRow alert", <TableExpandedRow key="r2" state="alert">findings</TableExpandedRow>],
    ["QueryBar", <QueryBar key="q1" query="exposed=true risk=critical" matchCount={7} />],
    [
      "Tabs",
      <Tabs key="t1" defaultValue="a">
        <TabsList>
          <TabsTrigger value="a">A</TabsTrigger>
          <TabsTrigger value="b">B</TabsTrigger>
        </TabsList>
        <TabsContent value="a">a</TabsContent>
      </Tabs>,
    ],
  ])("%s renders without forbidden classes or inline shadows", (_name, element) => {
    const { container } = render(element);
    assertNoForbiddenClasses(container);
  });
});

describe("Pill discriminated union", () => {
  it("EXPOSED maps to alert tone", () => {
    const { container } = render(<Pill kind="EXPOSED" />);
    const cls = container.firstElementChild?.className ?? "";
    expect(cls).toMatch(/text-alert/);
    expect(cls).toMatch(/bg-alert-bg/);
    expect(container.textContent).toBe("EXPOSED");
  });

  it("TOR maps to warn tone", () => {
    const { container } = render(<Pill kind="TOR" />);
    expect(container.firstElementChild?.className).toMatch(/text-warn/);
  });

  it("CVE critical maps to alert; CVE medium maps to warn", () => {
    const { container: critical } = render(<Pill kind="CVE" severity="critical" />);
    const { container: medium } = render(<Pill kind="CVE" severity="medium" />);
    expect(critical.firstElementChild?.className).toMatch(/text-alert/);
    expect(medium.firstElementChild?.className).toMatch(/text-warn/);
  });

  it("OK maps to ok tone", () => {
    const { container } = render(<Pill kind="OK" />);
    expect(container.firstElementChild?.className).toMatch(/text-ok/);
  });

  it("renders the controlled vocabulary word as text", () => {
    for (const kind of ["EXPOSED", "STALE", "TOR", "OK"] as const) {
      const { container } = render(<Pill kind={kind} />);
      expect(container.textContent).toBe(kind);
    }
    const { container: cve } = render(<Pill kind="CVE" severity="low" />);
    expect(cve.textContent).toBe("CVE");
  });
});

describe("Button variants", () => {
  it("secondary is the default", () => {
    const { getByRole } = render(<Button>x</Button>);
    expect(getByRole("button").getAttribute("data-variant")).toBe("secondary");
  });

  it("l402 prefixes the bolt glyph", () => {
    const { getByRole } = render(<Button variant="l402">unlock</Button>);
    const btn = getByRole("button");
    expect(btn.getAttribute("data-variant")).toBe("l402");
    // ⚡ glyph appears as a child span.
    expect(btn.textContent).toContain(GLYPHS.bolt);
  });

  it("l402 carries primary tokens (the only loud CTA)", () => {
    const { getByRole } = render(<Button variant="l402">x</Button>);
    const cls = getByRole("button").className;
    expect(cls).toMatch(/text-primary/);
    expect(cls).toMatch(/border-primary/);
    expect(cls).toMatch(/bg-l402-bg/);
  });

  it("secondary does NOT carry primary tokens", () => {
    const { getByRole } = render(<Button>x</Button>);
    const cls = getByRole("button").className;
    expect(cls).not.toMatch(/-primary/);
  });
});

describe("Glyph allow-list", () => {
  it("renders the unicode for each name", () => {
    const names: Array<keyof typeof GLYPHS> = [
      "chevron", "caret", "dot", "bolt", "search", "cross", "warn", "sep", "cmd",
    ];
    for (const n of names) {
      const { container } = render(<Glyph name={n} />);
      expect(container.textContent).toBe(GLYPHS[n]);
    }
  });
});

describe("QueryBar grammar", () => {
  it("parseQuery extracts ordered key/value pairs", () => {
    expect(parseQuery("risk=critical country=DE")).toEqual([
      { key: "risk", value: "critical" },
      { key: "country", value: "DE" },
    ]);
  });

  it("parseQuery drops tokens without `=`", () => {
    expect(parseQuery("risk=critical bareword country=DE")).toEqual([
      { key: "risk", value: "critical" },
      { key: "country", value: "DE" },
    ]);
  });

  it("alert-coded value renders text-alert", () => {
    const { container } = render(<QueryBar query="exposed=true" />);
    const alertSpan = Array.from(container.querySelectorAll("span")).find(
      (s) => s.textContent === "true",
    );
    expect(alertSpan?.className).toMatch(/text-alert/);
  });

  it("ok-coded value renders text-ok", () => {
    const { container } = render(<QueryBar query="tor=false" />);
    const okSpan = Array.from(container.querySelectorAll("span")).find(
      (s) => s.textContent === "false",
    );
    expect(okSpan?.className).toMatch(/text-ok/);
  });
});

describe("StatTile delta direction", () => {
  it("rising-bad delta uses text-alert", () => {
    const { container } = render(
      <StatTile label="EXPOSED" value={42} delta={{ value: "+3", direction: "rising-bad" }} />,
    );
    const delta = Array.from(container.querySelectorAll("span")).find(
      (s) => s.textContent === "+3",
    );
    expect(delta?.className).toMatch(/text-alert/);
  });

  it("rising-good delta uses text-ok", () => {
    const { container } = render(
      <StatTile label="OK" value={100} delta={{ value: "+5", direction: "rising-good" }} />,
    );
    const delta = Array.from(container.querySelectorAll("span")).find(
      (s) => s.textContent === "+5",
    );
    expect(delta?.className).toMatch(/text-ok/);
  });
});

describe("TableRow selection state", () => {
  it("selected row carries the 2px primary left border", () => {
    const { container } = render(<TableRow selected>row</TableRow>);
    const cls = container.firstElementChild?.className ?? "";
    expect(cls).toMatch(/border-l-primary/);
    expect(cls).toMatch(/border-l-2/);
  });

  it("non-selected row does not carry primary", () => {
    const { container } = render(<TableRow>row</TableRow>);
    expect(container.firstElementChild?.className).not.toMatch(/-primary/);
  });
});
