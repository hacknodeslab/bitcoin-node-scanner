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
import type { ScanJobOut } from "@/lib/api/types";

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

describe("ExplorerFooter", () => {
  it("renders the focus and palette hints", () => {
    render(<ExplorerFooter />);
    const f = screen.getByTestId("explorer-footer");
    expect(f.textContent).toContain("focus query");
    expect(f.textContent?.toLowerCase()).toContain("palette");
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
