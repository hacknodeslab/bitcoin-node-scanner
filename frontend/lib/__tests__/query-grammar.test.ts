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

  it("example=false → filters.is_example=false; example=true → true", () => {
    expect(parseQueryToFilters("example=false").filters).toEqual({ is_example: false });
    expect(parseQueryToFilters("example=true").filters).toEqual({ is_example: true });
  });

  it("example=maybe → warning, no filter", () => {
    const r = parseQueryToFilters("example=maybe");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/example=maybe/);
  });
  it("port=8333 → filters.port=8333", () => {
    expect(parseQueryToFilters("port=8333").filters).toEqual({ port: 8333 });
  });

  it("port=abc → warning, no filter", () => {
    const r = parseQueryToFilters("port=abc");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/port=abc/);
  });

  it("port=0 → warning, no filter", () => {
    const r = parseQueryToFilters("port=0");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/port=0/);
  });

  it("port out of range → warning, no filter", () => {
    const r = parseQueryToFilters("port=99999");
    expect(r.filters).toEqual({});
    expect(r.warnings.join(" ")).toMatch(/port=99999/);
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

describe("blocklist keys", () => {
  it("blocklisted=true sets the flag", () => {
    const r = parseQueryToFilters("blocklisted=true");
    expect(r.filters).toEqual({ blocklisted: true });
    expect(r.warnings).toEqual([]);
  });

  it("blocklisted=false is rejected with a warning", () => {
    const r = parseQueryToFilters("blocklisted=false");
    expect(r.filters).toEqual({});
    expect(r.warnings[0]).toMatch(/not supported/);
  });

  it("blocklist=<id> accepts known ids case-insensitively", () => {
    const r = parseQueryToFilters("blocklist=Spamhaus_DROP risk=low");
    expect(r.filters).toEqual({ blocklist: "spamhaus_drop", risk_level: "LOW" });
  });

  it("blocklist with an unknown id warns and lists the valid ids", () => {
    const r = parseQueryToFilters("blocklist=greynoise");
    expect(r.filters).toEqual({});
    expect(r.warnings[0]).toContain("firehol_level1|spamhaus_drop|feodo|tor_exit");
  });
});

describe("ip search", () => {
  it("ip=<addr> filters by exact IP", () => {
    const r = parseQueryToFilters("ip=23.176.184.73");
    expect(r.filters).toEqual({ ip: "23.176.184.73" });
    expect(r.warnings).toEqual([]);
  });

  it("a bare IPv4 is shorthand for ip=", () => {
    const r = parseQueryToFilters("23.176.184.73");
    expect(r.filters).toEqual({ ip: "23.176.184.73" });
    expect(r.warnings).toEqual([]);
  });

  it("a bare IPv6 (with or without brackets) is shorthand for ip=", () => {
    expect(parseQueryToFilters("2001:db8::1").filters).toEqual({ ip: "2001:db8::1" });
    expect(parseQueryToFilters("[2001:db8::1]").filters).toEqual({ ip: "2001:db8::1" });
  });

  it("a bare IP composes with other keys", () => {
    const r = parseQueryToFilters("risk=critical 10.0.0.1");
    expect(r.filters).toEqual({ risk_level: "CRITICAL", ip: "10.0.0.1" });
  });

  it("an invalid ip value warns", () => {
    const r = parseQueryToFilters("ip=999.1.1.1");
    expect(r.filters).toEqual({});
    expect(r.warnings[0]).toMatch(/IPv4 or IPv6/);
  });

  it("non-IP bare words warn instead of being silently ignored", () => {
    const r = parseQueryToFilters("bitcoin risk=low");
    expect(r.filters).toEqual({ risk_level: "LOW" });
    expect(r.warnings).toEqual(['"bitcoin" ignored: use key=value (e.g. ip=1.2.3.4 or risk=high)']);
  });
});

describe("abuseipdb keys", () => {
  it("abuse_min=N accepts 0-100", () => {
    expect(parseQueryToFilters("abuse_min=75").filters).toEqual({ abuse_min: 75 });
    expect(parseQueryToFilters("abuse_min=101").warnings[0]).toMatch(/between 0 and 100/);
    expect(parseQueryToFilters("abuse_min=high").filters).toEqual({});
  });

  it("reported=true only", () => {
    expect(parseQueryToFilters("reported=true").filters).toEqual({ reported: true });
    const r = parseQueryToFilters("reported=false");
    expect(r.filters).toEqual({});
    expect(r.warnings[0]).toMatch(/not supported/);
  });
});

describe("tokensToFilters direct entry point", () => {
  it("accepts already-parsed tokens", () => {
    const r = tokensToFilters([{ key: "risk", value: "critical" }]);
    expect(r.filters.risk_level).toBe("CRITICAL");
  });
});
