/**
 * StatsStrip renders the five tokens (TOTAL/EXPOSED/STALE/TOR/OK) from
 * `/api/v1/stats` and a footer with last_scan_at + commit. Tests pass `data`
 * directly so we don't have to mock SWR; the component prefers props over
 * the hook when both exist.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { StatsStrip } from "../explorer/StatsStrip";
import type { StatsOut } from "@/lib/api/types";

const FIXTURE: StatsOut = {
  total_nodes: 412,
  by_risk_level: { LOW: 249, MEDIUM: 160, HIGH: 1, CRITICAL: 2 },
  by_country: {},
  vulnerable_nodes_count: 0,
  exposed_count: 2,
  stale_count: 412,
  tor_count: 0,
  ok_count: 5,
  stale_threshold_days: 7,
  last_scan_at: "2026-04-26T12:00:00Z",
  commit: "abc1234",
};

const TILE_KEYS = ["TOTAL", "EXPOSED", "STALE", "TOR", "OK"] as const;

describe("StatsStrip", () => {
  it("renders all five tiles in order", () => {
    const { container } = render(<StatsStrip data={FIXTURE} />);
    const tiles = container.querySelectorAll("[data-testid^='stat-tile-']");
    expect(Array.from(tiles).map((t) => t.getAttribute("data-testid"))).toEqual(
      TILE_KEYS.map((k) => `stat-tile-${k}`),
    );
  });

  it("each tile renders the right label and value", () => {
    render(<StatsStrip data={FIXTURE} />);
    const expected: Array<[string, string, string]> = [
      ["TOTAL", "TOTAL", "412"],
      ["EXPOSED", "EXPOSED", "2"],
      ["STALE", "STALE >7D", "412"],
      ["TOR", "TOR", "0"],
      ["OK", "OK", "5"],
    ];
    for (const [key, label, value] of expected) {
      const tile = screen.getByTestId(`stat-tile-${key}`);
      expect(tile.textContent).toContain(label);
      expect(tile.textContent).toContain(value);
    }
  });

  it("echoes the threshold-days in the STALE label", () => {
    render(<StatsStrip data={{ ...FIXTURE, stale_threshold_days: 14 }} />);
    expect(screen.getByTestId("stat-tile-STALE").textContent).toContain("STALE >14D");
  });

  it("renders the footer with last_scan_at + commit", () => {
    render(<StatsStrip data={FIXTURE} />);
    const footer = screen.getByTestId("stats-strip-footer");
    expect(footer.textContent).toContain("2026-04-26 12:00 UTC");
    expect(footer.textContent).toContain("build abc1234");
  });

  it("shows '—' when last_scan_at is null and omits the build segment when commit is null", () => {
    render(
      <StatsStrip data={{ ...FIXTURE, last_scan_at: null, commit: null }} />,
    );
    const footer = screen.getByTestId("stats-strip-footer");
    expect(footer.textContent).toBe("last scan —");
  });

  it("renders skeleton placeholders when loading", () => {
    render(<StatsStrip loading />);
    expect(screen.getByTestId("stats-strip-loading")).toBeTruthy();
    for (const key of TILE_KEYS) {
      expect(screen.getByTestId(`stat-tile-${key}`).textContent).toContain("…");
    }
  });

  it("renders alert text when error is set", () => {
    render(<StatsStrip error={new Error("boom")} />);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("stats failed to load");
  });
});
