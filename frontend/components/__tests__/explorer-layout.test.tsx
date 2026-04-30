/**
 * Explorer layout smoke tests for §8.1.
 *
 * The page composition is too heavy to render fully (StatsStrip mounts SWR
 * and tries to fetch). We test the leaf layout components in isolation —
 * TopNav, NodeTablePlaceholder, ExplorerFooter — to catch structural drift
 * without dragging in the network layer.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { Brand } from "../brand/Brand";
import { TopNav } from "../explorer/TopNav";
import { ExplorerFooter } from "../explorer/ExplorerFooter";
import { NodeTable } from "../explorer/NodeTable";
import { ThemeProvider } from "../providers/ThemeProvider";
import type { NodeOut, ScanJobOut } from "@/lib/api/types";

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
  it("renders the brand, theme toggle, and the ⌘K palette hint", () => {
    render(
      <ThemeProvider>
        <TopNav />
      </ThemeProvider>,
    );
    expect(screen.getByTestId("brand")).toBeTruthy();
    expect(screen.getByTestId("theme-toggle")).toBeTruthy();
    const nav = screen.getByTestId("top-nav");
    expect(nav.textContent).toContain("K");
    expect(nav.textContent?.toLowerCase()).toContain("palette");
  });
});

describe("ExplorerFooter", () => {
  it("renders the focus and palette hints", () => {
    render(<ExplorerFooter />);
    const f = screen.getByTestId("explorer-footer");
    expect(f.textContent).toContain("focus query");
    expect(f.textContent?.toLowerCase()).toContain("palette");
  });

  it("renders data sources (Shodan, NVD, MaxMind GeoIP)", () => {
    render(<ExplorerFooter />);
    const sources = screen.getByTestId("footer-sources");
    expect(sources.textContent).toContain("Shodan");
    expect(sources.textContent).toContain("NVD");
    expect(sources.textContent).toContain("MaxMind GeoIP");
  });

  it("renders a research-only disclaimer", () => {
    render(<ExplorerFooter />);
    const d = screen.getByTestId("footer-disclaimer");
    expect(d.textContent?.toLowerCase()).toContain("research");
    // Disclaimer must not be aria-hidden — it has to be reachable by screen readers.
    expect(d.getAttribute("aria-hidden")).not.toBe("true");
  });

  it("idle state: button label 'run scan' and enabled", () => {
    render(<ExplorerFooter />);
    const btn = screen.getByTestId("scan-trigger") as HTMLButtonElement;
    expect(btn.textContent).toContain("run scan");
    expect(btn.disabled).toBe(false);
    expect(screen.queryByTestId("scan-status")).toBeNull();
  });

  it("running state: button disabled, status reads 'scanning…'", () => {
    const job: ScanJobOut = {
      job_id: "j1",
      status: "running",
      started_at: null,
      finished_at: null,
      result_summary: null,
    };
    render(<ExplorerFooter job={job} busyOverride />);
    const btn = screen.getByTestId("scan-trigger") as HTMLButtonElement;
    expect(btn.textContent).toContain("scanning");
    expect(btn.disabled).toBe(true);
    expect(screen.getByTestId("scan-status").textContent).toContain("scanning");
  });

  it("completed state: status reads 'done' with ok tone", () => {
    const job: ScanJobOut = {
      job_id: "j1",
      status: "completed",
      started_at: null,
      finished_at: null,
      result_summary: null,
    };
    render(<ExplorerFooter job={job} />);
    const status = screen.getByTestId("scan-status");
    expect(status.textContent).toContain("done");
    expect(status.className).toMatch(/text-ok/);
  });

  it("failed state: status reads 'failed' with alert tone", () => {
    const job: ScanJobOut = {
      job_id: "j1",
      status: "failed",
      started_at: null,
      finished_at: null,
      result_summary: null,
    };
    render(<ExplorerFooter job={job} />);
    const status = screen.getByTestId("scan-status");
    expect(status.textContent).toContain("failed");
    expect(status.className).toMatch(/text-alert/);
  });

  it("clicking the button calls onStart", () => {
    const onStart = vi.fn();
    render(<ExplorerFooter onStart={onStart} />);
    fireEvent.click(screen.getByTestId("scan-trigger"));
    expect(onStart).toHaveBeenCalledTimes(1);
  });

  it("surfaces start errors inline without crashing", async () => {
    const onStart = vi.fn().mockRejectedValue(new Error("missing api key"));
    render(<ExplorerFooter onStart={onStart} />);
    fireEvent.click(screen.getByTestId("scan-trigger"));
    // Wait a microtask for the rejection to settle.
    await Promise.resolve();
    await Promise.resolve();
    const err = await screen.findByTestId("scan-start-error");
    expect(err.textContent).toContain("missing api key");
  });
});

describe("Viewport-bounded NodeTable layout", () => {
  // Build a tall fixture — many rows — and assert that the body wrapper
  // is the scrolling container, not the document.
  const BASE_NODE: Omit<NodeOut, "id" | "ip"> = {
    port: 8333,
    version: "0.21.0",
    user_agent: null,
    protocol_version: null,
    services: null,
    risk_level: "LOW",
    is_vulnerable: false,
    has_exposed_rpc: false,
    is_dev_version: false,
    country_code: null,
    country_name: null,
    city: null,
    subdivision: null,
    asn: null,
    asn_name: null,
    geo_country_code: null,
    geo_country_name: null,
    first_seen: "2026-04-26T10:00:00Z",
    last_seen: "2026-04-26T10:00:00Z",
    hostname: null,
    os_info: null,
    isp: null,
    org: null,
    open_ports: null,
    vulns: null,
    tags: null,
    cpe: null,
  };

  it("body wrapper has overflow-y-auto and flex-1 min-h-0 utility classes", () => {
    const nodes: NodeOut[] = Array.from({ length: 50 }, (_, i) => ({
      ...BASE_NODE,
      id: i + 1,
      ip: `10.0.0.${i + 1}`,
    }));
    render(<NodeTable nodes={nodes} />);
    const body = screen.getByTestId("node-table-body");
    expect(body.className).toMatch(/overflow-y-auto/);
    expect(body.className).toMatch(/flex-1/);
    expect(body.className).toMatch(/min-h-0/);
  });
});
