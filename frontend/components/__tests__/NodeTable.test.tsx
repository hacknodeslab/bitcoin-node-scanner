/**
 * NodeTable wires sortable headers, inline row expansion, and the FLAGS
 * pill set. Tests inject `nodes` directly so SWR doesn't run.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SWRConfig } from "swr";
import type { ReactNode } from "react";

import { NodeTable } from "../explorer/NodeTable";
import type { NodeOut } from "@/lib/api/types";

// Wrap renders in a fresh SWR cache so tests don't share fetched data via the
// module-global cache. Without this, useSWR sees cached data from a prior
// test and skips the fetcher entirely → fetchMock never fires.
function FreshSWR({ children }: { children: ReactNode }) {
  return <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>;
}

const BASE: Omit<NodeOut, "ip" | "port" | "id"> = {
  version: "0.21.0",
  user_agent: "/Satoshi:0.21.0/",
  protocol_version: 70015,
  services: null,
  risk_level: "LOW",
  is_vulnerable: false,
  has_exposed_rpc: false,
  is_dev_version: false,
  is_example: false,
  country_code: "US",
  country_name: "United States",
  city: null,
  subdivision: null,
  asn: "AS1234",
  asn_name: null,
  geo_country_code: null,
  geo_country_name: null,
  first_seen: "2026-04-20T10:00:00Z",
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

const NODE_LOW: NodeOut = { ...BASE, id: 1, ip: "1.1.1.1", port: 8333 };
const NODE_EXPOSED: NodeOut = {
  ...BASE,
  id: 2,
  ip: "2.2.2.2",
  port: 8332,
  has_exposed_rpc: true,
  risk_level: "CRITICAL",
};
const NODE_TOR: NodeOut = {
  ...BASE,
  id: 3,
  ip: "3.3.3.3",
  port: 8333,
  hostname: "abc.onion",
  tags: ["tor"],
};
const NODE_STALE: NodeOut = {
  ...BASE,
  id: 4,
  ip: "4.4.4.4",
  port: 8333,
  last_seen: "2026-01-01T00:00:00Z", // many months old
};
const NODE_VULN: NodeOut = {
  ...BASE,
  id: 5,
  ip: "5.5.5.5",
  port: 8333,
  is_vulnerable: true,
  risk_level: "HIGH",
};

describe("NodeTable", () => {
  it("renders one row per node", () => {
    render(<NodeTable nodes={[NODE_LOW, NODE_EXPOSED]} />);
    expect(screen.getByTestId("node-row-1.1.1.1")).toBeTruthy();
    expect(screen.getByTestId("node-row-2.2.2.2")).toBeTruthy();
  });

  it("EXPOSED node colours the port in alert + shows the EXPOSED pill", () => {
    render(<NodeTable nodes={[NODE_EXPOSED]} />);
    const row = screen.getByTestId("node-row-2.2.2.2");
    const pill = row.querySelector('[data-pill-kind="EXPOSED"]');
    expect(pill).toBeTruthy();
    // The port span carries text-alert when exposed.
    expect(row.innerHTML).toContain("text-alert");
  });

  it("TOR node renders a TOR pill", () => {
    render(<NodeTable nodes={[NODE_TOR]} />);
    const row = screen.getByTestId("node-row-3.3.3.3");
    expect(row.querySelector('[data-pill-kind="TOR"]')).toBeTruthy();
  });

  it("STALE node renders a STALE pill (last_seen older than 7 days)", () => {
    render(<NodeTable nodes={[NODE_STALE]} />);
    const row = screen.getByTestId("node-row-4.4.4.4");
    expect(row.querySelector('[data-pill-kind="STALE"]')).toBeTruthy();
  });

  it("vulnerable HIGH node renders a CVE pill with high severity", () => {
    render(<NodeTable nodes={[NODE_VULN]} />);
    const row = screen.getByTestId("node-row-5.5.5.5");
    const pill = row.querySelector('[data-pill-kind="CVE"]');
    expect(pill).toBeTruthy();
    // toneFor maps high → alert (text-alert / bg-alert-bg)
    expect(pill?.className).toMatch(/text-alert/);
  });

  it("EXAMPLE node renders the EXAMPLE pill and the row carries the example accent", () => {
    const exampleNode: NodeOut = { ...BASE, id: 9, ip: "1.2.3.4", port: 8333, is_example: true };
    render(<NodeTable nodes={[exampleNode]} />);
    const row = screen.getByTestId("node-row-1.2.3.4");
    expect(row.dataset.example).toBe("true");
    expect(row.className).toMatch(/bg-example-bg/);
    expect(row.className).toMatch(/border-example/);
    expect(row.querySelector('[data-pill-kind="EXAMPLE"]')).toBeTruthy();
  });

  it("non-EXAMPLE row has no EXAMPLE pill and no example accent class", () => {
    render(<NodeTable nodes={[NODE_LOW]} />);
    const row = screen.getByTestId("node-row-1.1.1.1");
    expect(row.dataset.example).toBeUndefined();
    expect(row.className).not.toMatch(/bg-example-bg/);
    expect(row.querySelector('[data-pill-kind="EXAMPLE"]')).toBeNull();
  });

  it("clicking a row calls onSelectNode with that IP", () => {
    const onSelectNode = vi.fn();
    render(<NodeTable nodes={[NODE_LOW, NODE_EXPOSED]} onSelectNode={onSelectNode} />);
    fireEvent.click(screen.getByTestId("node-row-2.2.2.2"));
    expect(onSelectNode).toHaveBeenCalledWith("2.2.2.2");
  });

  it("selectedIp marks the matching row with data-selected", () => {
    render(<NodeTable nodes={[NODE_LOW, NODE_EXPOSED]} selectedIp="2.2.2.2" />);
    expect(screen.getByTestId("node-row-2.2.2.2").getAttribute("data-selected")).toBe("true");
    expect(screen.getByTestId("node-row-1.1.1.1").getAttribute("data-selected")).toBeNull();
  });

  it("clicking a sortable header toggles sort direction; aria-sort tracks the active column", () => {
    render(<NodeTable nodes={[NODE_LOW]} />);
    const ipButton = screen.getByTestId("sort-ip");
    const ipCell = ipButton.closest('[role="columnheader"]')!;
    expect(ipCell.getAttribute("aria-sort")).toBe("none");
    fireEvent.click(ipButton);
    expect(ipCell.getAttribute("aria-sort")).toBe("ascending");
    fireEvent.click(ipButton);
    expect(ipCell.getAttribute("aria-sort")).toBe("descending");
  });

  it("FLAGS column header is not interactive", () => {
    render(<NodeTable nodes={[NODE_LOW]} />);
    expect(screen.queryByTestId("sort-flags")).toBeNull();
  });

  it("renders empty-state line when nodes=[] and no error", () => {
    render(<NodeTable nodes={[]} />);
    expect(screen.getByText(/no nodes match/)).toBeTruthy();
  });

  it("renders alert when error is set", () => {
    render(<NodeTable error={new Error("boom")} />);
    expect(screen.getByRole("alert").textContent).toContain("nodes failed to load");
  });

  it("does not render pagination when nodes are injected (test mode)", () => {
    render(<NodeTable nodes={[NODE_LOW]} />);
    expect(screen.queryByTestId("pagination")).toBeNull();
  });
});

describe("NodeTable pagination (live SWR)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  function makeListResponse(items: Partial<NodeOut>[], total: number): Response {
    const filled = items.map((p, i) => ({ ...BASE, id: 100 + i, ip: `9.0.0.${i}`, port: 8333, ...p }));
    return new Response(JSON.stringify(filled), {
      status: 200,
      headers: { "content-type": "application/json", "X-Total-Count": String(total) },
    });
  }

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function waitForLastFetchUrl(predicate: (url: URL) => boolean): Promise<URL> {
    let last: URL | null = null;
    await vi.waitFor(() => {
      const calls = fetchMock.mock.calls;
      if (calls.length === 0) throw new Error("no fetch calls yet");
      const u = new URL(calls[calls.length - 1][0] as string);
      if (!predicate(u)) throw new Error(`url did not satisfy predicate: ${u.toString()}`);
      last = u;
    });
    return last!;
  }

  it("first load fetches limit=25 offset=0 and shows 'Page 1 of N'", async () => {
    fetchMock.mockResolvedValue(makeListResponse([{}, {}, {}], 80));
    render(<FreshSWR><NodeTable /></FreshSWR>);
    const url = await waitForLastFetchUrl((u) => u.searchParams.get("limit") === "25");
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("offset")).toBe("0");
    const status = await screen.findByTestId("pagination-status");
    await vi.waitFor(() => {
      expect(status.textContent).toContain("Page 1 of 4");
      expect(status.textContent).toContain("80 results");
    });
  });

  it("clicking next advances offset to pageSize", async () => {
    fetchMock.mockResolvedValue(makeListResponse(new Array(25).fill({}), 80));
    render(<FreshSWR><NodeTable /></FreshSWR>);
    // Wait for the initial fetch to settle so the next-button is enabled.
    await waitForLastFetchUrl((u) => u.searchParams.get("offset") === "0");
    const next = (await screen.findByTestId("pagination-next")) as HTMLButtonElement;
    await vi.waitFor(() => expect(next.disabled).toBe(false));
    fireEvent.click(next);
    await waitForLastFetchUrl((u) => u.searchParams.get("offset") === "25");
  });

  it("prev is disabled on page 1", async () => {
    fetchMock.mockResolvedValue(makeListResponse([{}, {}], 30));
    render(<FreshSWR><NodeTable /></FreshSWR>);
    const prev = (await screen.findByTestId("pagination-prev")) as HTMLButtonElement;
    expect(prev.disabled).toBe(true);
  });

  it("next is disabled on the last page", async () => {
    // total=20, pageSize=25 → only one page
    fetchMock.mockResolvedValue(makeListResponse(new Array(20).fill({}), 20));
    render(<FreshSWR><NodeTable /></FreshSWR>);
    await waitForLastFetchUrl((u) => u.searchParams.get("offset") === "0");
    const next = (await screen.findByTestId("pagination-next")) as HTMLButtonElement;
    await vi.waitFor(() => expect(next.disabled).toBe(true));
  });

  it("changing page size refetches with offset 0", async () => {
    fetchMock.mockResolvedValue(makeListResponse(new Array(25).fill({}), 200));
    render(<FreshSWR><NodeTable /></FreshSWR>);
    await waitForLastFetchUrl((u) => u.searchParams.get("limit") === "25");
    fireEvent.change(screen.getByTestId("pagination-page-size"), { target: { value: "100" } });
    const url = await waitForLastFetchUrl((u) => u.searchParams.get("limit") === "100");
    expect(url.searchParams.get("offset")).toBe("0");
  });
});
