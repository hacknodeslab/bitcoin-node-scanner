/**
 * Explorer layout smoke tests for §8.1.
 *
 * The page composition is too heavy to render fully (StatsStrip mounts SWR
 * and tries to fetch). We test the leaf layout components in isolation —
 * TopNav, NodeTablePlaceholder, ExplorerFooter — to catch structural drift
 * without dragging in the network layer.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { Brand } from "../brand/Brand";
import { TopNav } from "../explorer/TopNav";
import { NodeTablePlaceholder } from "../explorer/NodeTablePlaceholder";
import { ExplorerFooter } from "../explorer/ExplorerFooter";

describe("Brand", () => {
  it("renders the bns / scanner mark with the orange accent on bns", () => {
    const { container } = render(<Brand />);
    const bns = container.querySelector(".text-primary");
    expect(bns?.textContent).toBe("bns");
  });

  it("hides the subtitle in compact mode", () => {
    render(<Brand compact />);
    expect(screen.queryByText("bitcoin node security recon")).toBeNull();
  });
});

describe("TopNav", () => {
  it("renders the brand and the ⌘K palette hint", () => {
    render(<TopNav />);
    expect(screen.getByTestId("brand")).toBeTruthy();
    const nav = screen.getByTestId("top-nav");
    expect(nav.textContent).toContain("K");
    expect(nav.textContent?.toLowerCase()).toContain("palette");
  });
});

describe("NodeTablePlaceholder", () => {
  it("renders all expected column headers", () => {
    render(<NodeTablePlaceholder />);
    const ph = screen.getByTestId("node-table-placeholder");
    for (const label of ["IP", "PORT", "VERSION", "CC", "RISK", "FLAGS"]) {
      expect(ph.textContent).toContain(label);
    }
  });

  it("shows a status note pointing to the §8.4 wiring task", () => {
    const { container } = render(<NodeTablePlaceholder />);
    expect(container.textContent).toContain("§8.4");
  });
});

describe("ExplorerFooter", () => {
  it("renders the focus and palette hints", () => {
    render(<ExplorerFooter />);
    const f = screen.getByTestId("explorer-footer");
    expect(f.textContent).toContain("focus query");
    expect(f.textContent?.toLowerCase()).toContain("palette");
  });
});
