/**
 * Palette ↔ REST parity (§9.4). Every non-NAV palette command MUST resolve
 * to a registered REST endpoint. NAV entries are frontend-only and exempt.
 */
import { describe, it, expect } from "vitest";
import { COMMAND_SPECS, REST_ENDPOINTS } from "../commands";

describe("palette ↔ REST parity", () => {
  for (const c of COMMAND_SPECS) {
    if (c.group === "NAV") continue;
    it(`${c.id} (${c.label}) resolves to a registered REST endpoint`, () => {
      expect(c.restEndpoint, `${c.id}: non-NAV command must declare restEndpoint`).not.toBeNull();
      expect(
        REST_ENDPOINTS.has(c.restEndpoint!),
        `${c.id} (${c.label}): "${c.restEndpoint}" not in REST_ENDPOINTS — drift between palette and FastAPI router`,
      ).toBe(true);
    });
  }

  it("NAV commands have restEndpoint=null (frontend-only)", () => {
    const navWithEndpoint = COMMAND_SPECS.filter(
      (c) => c.group === "NAV" && c.restEndpoint !== null,
    );
    expect(navWithEndpoint).toEqual([]);
  });

  it("ids are unique across the registry", () => {
    const ids = COMMAND_SPECS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
