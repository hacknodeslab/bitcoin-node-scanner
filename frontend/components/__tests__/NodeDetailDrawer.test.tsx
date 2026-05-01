/**
 * NodeDetailDrawer composition tests. The component pulls detail via
 * useNodeDetail; tests inject `detailOverride` so SWR doesn't run.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { NodeDetailDrawer } from "../explorer/NodeDetailDrawer";
import type { NodeOut } from "@/lib/api/types";

const NODE: NodeOut = {
  id: 1,
  ip: "1.2.3.4",
  port: 8333,
  version: "0.21.0",
  user_agent: "/Satoshi:0.21.0/",
  protocol_version: 70015,
  services: null,
  risk_level: "MEDIUM",
  is_vulnerable: false,
  has_exposed_rpc: false,
  is_dev_version: false,
  is_example: false,
  country_code: "DE",
  country_name: "Germany",
  city: null,
  subdivision: null,
  asn: "AS3320",
  asn_name: null,
  geo_country_code: null,
  geo_country_name: null,
  first_seen: null,
  last_seen: "2026-04-26T10:00:00Z",
  hostname: null,
  os_info: null,
  isp: null,
  org: null,
  open_ports: [
    { port: 8333, service: "bitcoin" },
    { port: 22, service: "ssh" },
  ],
  vulns: null,
  tags: ["bitcoin"],
  cpe: null,
};

const EXPOSED_NODE: NodeOut = {
  ...NODE,
  ip: "2.2.2.2",
  port: 8332,
  has_exposed_rpc: true,
  risk_level: "CRITICAL",
  vulns: ["CVE-2024-1234", "CVE-2024-5678"],
  is_vulnerable: true,
};

const HOOK_LOADED = (node: NodeOut | null) => ({
  detail: node ? { node, geo: null } : null,
  isLoading: false,
  error: null,
});

const HOOK_LOADING = {
  detail: null,
  isLoading: true,
  error: null,
};

const HOOK_ERROR = {
  detail: null,
  isLoading: false,
  error: new Error("boom"),
};

describe("NodeDetailDrawer", () => {
  it("does not render content when ip is null", () => {
    const { container } = render(
      <NodeDetailDrawer
        ip={null}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(null)}
      />,
    );
    // The Drawer primitive uses a Radix portal; nothing should mount when closed.
    expect(container.querySelector("[data-testid='drawer-header']")).toBeNull();
  });

  it("renders header with IP, port and last_seen", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    const header = screen.getByTestId("drawer-header");
    expect(header.textContent).toContain("1.2.3.4");
    expect(header.textContent).toContain("8333");
    expect(header.textContent).toContain("2026-04-26");
    expect(header.textContent).toContain("AS3320");
  });

  it("EXPOSED node colours the port in alert", () => {
    render(
      <NodeDetailDrawer
        ip={EXPOSED_NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(EXPOSED_NODE)}
      />,
    );
    const port = screen.getByTestId("drawer-port");
    expect(port.className).toMatch(/text-alert/);
    expect(port.textContent).toBe("8332");
  });

  it("renders tab counts: ports + vulnerabilities (alert when nonzero)", () => {
    render(
      <NodeDetailDrawer
        ip={EXPOSED_NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(EXPOSED_NODE)}
      />,
    );
    expect(screen.getByTestId("tab-count-ports").textContent).toBe("2");
    const vulns = screen.getByTestId("tab-count-vulns");
    expect(vulns.textContent).toBe("2");
    expect(vulns.className).toMatch(/text-alert/);
  });

  it("vulnerabilities count uses dim tone when zero", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    const vulns = screen.getByTestId("tab-count-vulns");
    expect(vulns.textContent).toBe("0");
    expect(vulns.className).not.toMatch(/text-alert/);
  });

  it("renders the open-ports card by default", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    const card = screen.getByTestId("card-ports");
    expect(card.textContent).toContain("bitcoin");
    expect(card.textContent).toContain("ssh");
  });

  it("loading state renders status line; error state renders alert", () => {
    const { rerender } = render(
      <NodeDetailDrawer
        ip="1.2.3.4"
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADING}
      />,
    );
    expect(screen.getByText(/loading detail/)).toBeTruthy();

    rerender(
      <NodeDetailDrawer
        ip="1.2.3.4"
        onOpenChange={() => {}}
        detailOverride={HOOK_ERROR}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain("failed to load");
  });

  it("sliver row click swaps the active IP without dismissing", () => {
    const onActivateIp = vi.fn();
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
        sliverNodes={[NODE, EXPOSED_NODE]}
        onActivateIp={onActivateIp}
      />,
    );
    fireEvent.click(screen.getByText(EXPOSED_NODE.ip));
    expect(onActivateIp).toHaveBeenCalledWith(EXPOSED_NODE.ip);
  });

  it("renders EXAMPLE badge in the header when node.is_example is true", () => {
    const exampleNode: NodeOut = { ...NODE, is_example: true };
    render(
      <NodeDetailDrawer
        ip={exampleNode.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(exampleNode)}
      />,
    );
    const header = screen.getByTestId("drawer-header");
    expect(header.dataset.example).toBe("true");
    expect(screen.getByText("EXAMPLE")).toBeTruthy();
  });

  it("does not render EXAMPLE badge when node.is_example is false", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    const header = screen.getByTestId("drawer-header");
    expect(header.dataset.example).toBeUndefined();
    expect(screen.queryByText("EXAMPLE")).toBeNull();
  });

  it("L402 button click reaches fetchL402Example and surfaces the challenge note", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "l402_pending" }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "www-authenticate": 'L402 macaroon="m", invoice="i"',
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    fireEvent.click(screen.getByTestId("drawer-l402-button"));
    const note = await screen.findByTestId("drawer-l402-note");
    expect(note.textContent).toContain("l402 not yet available");

    vi.unstubAllGlobals();
  });
});
