/**
 * Query-grammar bridge: maps the QueryBar's parsed key=value tokens into
 * NodeListParams shape, with diagnostics for unsupported keys/values.
 */
import { describe, it, expect } from "vitest";
import { parseQueryToFilters, tokensToFilters } from "../query-grammar";

describe("parseQueryToFilters", () => {
  it("empty input → empty filters and no warnings", () => {
    const r = parseQueryToFilters("");
    expect(r.filters).toEqual({});
    expect(r.warnings).toEqual([]);
  });

  it("risk=critical → filters.risk_level=CRITICAL (case-insensitive)", () => {
    expect(parseQueryToFilters("risk=critical").filters).toEqual({ risk_level: "CRITICAL" });
    expect(parseQueryToFilters("risk=High").filters).toEqual({ risk_level: "HIGH" });
  });

  it("invalid risk value → warning, no filter", () => {
    const r = parseQueryToFilters("risk=neon");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/risk=neon/);
  });

  it("country=Spain → filters.country='Spain' (preserves case)", () => {
    expect(parseQueryToFilters("country=Spain").filters).toEqual({ country: "Spain" });
  });

  it("exposed=true|false → boolean; '1'/'yes'/'no' also accepted", () => {
    expect(parseQueryToFilters("exposed=true").filters).toEqual({ exposed: true });
    expect(parseQueryToFilters("exposed=false").filters).toEqual({ exposed: false });
    expect(parseQueryToFilters("exposed=1").filters).toEqual({ exposed: true });
    expect(parseQueryToFilters("exposed=no").filters).toEqual({ exposed: false });
  });

  it("exposed=maybe → warning, no filter", () => {
    const r = parseQueryToFilters("exposed=maybe");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/exposed=maybe/);
  });

  it("tor=true → filters.tor=true; tor=false → warning (v0 unsupported)", () => {
    expect(parseQueryToFilters("tor=true").filters).toEqual({ tor: true });
    const r = parseQueryToFilters("tor=false");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/tor=false is not supported/);
  });

  it("unknown key → warning, no filter", () => {
    const r = parseQueryToFilters("color=orange");
    expect(r.filters).toEqual({});
    expect(r.warnings).toContain("unknown key: color");
  });

  it("multiple tokens compose into one filters object", () => {
    const r = parseQueryToFilters("risk=critical exposed=true country=Germany");
    expect(r.filters).toEqual({
      risk_level: "CRITICAL",
      exposed: true,
      country: "Germany",
    });
    expect(r.warnings).toEqual([]);
  });

  it("warnings accumulate when several tokens are bad", () => {
    const r = parseQueryToFilters("risk=neon foo=bar tor=false");
    expect(r.filters).toEqual({});
    expect(r.warnings.length).toBe(3);
  });
});

describe("tokensToFilters direct entry point", () => {
  it("accepts already-parsed tokens", () => {
    const r = tokensToFilters([{ key: "risk", value: "critical" }]);
    expect(r.filters.risk_level).toBe("CRITICAL");
  });
});
