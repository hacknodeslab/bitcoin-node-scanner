/**
 * NodeDetailDrawer composition tests. The component pulls detail via
 * useNodeDetail; tests inject `detailOverride` so SWR doesn't run.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { NodeDetailDrawer } from "../explorer/NodeDetailDrawer";
import type { NodeDetailOut } from "@/lib/api/types";

const NODE: NodeDetailOut = {
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
  latitude: null,
  longitude: null,
  first_seen: null,
  last_seen: "2026-04-26T10:00:00Z",
  banner: null,
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
  cve_count: 0,
  top_cve: null,
  cves: [],
};

const EXPOSED_NODE: NodeDetailOut = {
  ...NODE,
  ip: "2.2.2.2",
  port: 8332,
  has_exposed_rpc: true,
  risk_level: "CRITICAL",
  is_vulnerable: true,
  cve_count: 2,
  cves: [
    {
      cve_id: "CVE-2024-1234",
      severity: "HIGH",
      cvss_score: 7.5,
      description: null,
      detected_at: null,
      detected_version: null,
      resolved_at: null,
    },
    {
      cve_id: "CVE-2024-5678",
      severity: "CRITICAL",
      cvss_score: 9.8,
      description: null,
      detected_at: null,
      detected_version: null,
      resolved_at: null,
    },
  ],
};

const HOOK_LOADED = (node: NodeDetailOut | null) => ({
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
    const exampleNode: NodeDetailOut = { ...NODE, ip: "192.0.2.7", is_example: true };
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

  it("renders DEV pill when is_dev_version is true", () => {
    const dev: NodeDetailOut = { ...NODE, is_dev_version: true };
    render(
      <NodeDetailDrawer
        ip={dev.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(dev)}
      />,
    );
    expect(screen.getByText("DEV")).toBeTruthy();
  });

  it("does not render DEV pill when is_dev_version is false", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    expect(screen.queryByText("DEV")).toBeNull();
  });

  it("renders one Pill per tag, including reserved TOR/BITCOIN", () => {
    const torNode: NodeDetailOut = { ...NODE, tags: ["bitcoin", "tor"] };
    render(
      <NodeDetailDrawer
        ip={torNode.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(torNode)}
      />,
    );
    const header = screen.getByTestId("drawer-header");
    expect(header.querySelector('[data-pill-kind="BITCOIN"]')).toBeTruthy();
    expect(header.querySelector('[data-pill-kind="TOR"]')).toBeTruthy();
  });

  it("renders a generic TAG pill for unknown tag names", () => {
    const node: NodeDetailOut = { ...NODE, tags: ["custom-fork"] };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
      />,
    );
    const header = screen.getByTestId("drawer-header");
    const tag = header.querySelector('[data-pill-kind="TAG"]');
    expect(tag).toBeTruthy();
    expect(tag?.textContent).toBe("CUSTOM-FORK");
  });

  it("renders a RISK pill whose label is the severity uppercased", () => {
    render(
      <NodeDetailDrawer
        ip={EXPOSED_NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(EXPOSED_NODE)}
      />,
    );
    const header = screen.getByTestId("drawer-header");
    const risk = header.querySelector('[data-pill-kind="RISK"]');
    expect(risk).toBeTruthy();
    expect(risk?.textContent).toBe("CRITICAL");
  });

  it("subtitle shows version + locality and omits the MaxMind suffix when countries match", () => {
    const node: NodeDetailOut = {
      ...NODE,
      version: "Satoshi:29.0.0",
      city: "Reston",
      subdivision: "Virginia",
      country_code: "US",
      country_name: "United States",
      geo_country_code: "US",
      geo_country_name: "United States",
    };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
      />,
    );
    const subtitle = screen.getByTestId("drawer-subtitle").textContent ?? "";
    expect(subtitle).toContain("Satoshi:29.0.0");
    expect(subtitle).toContain("Reston, Virginia, United States");
    expect(subtitle).not.toContain("MM:");
  });

  it("subtitle appends the MaxMind suffix when Shodan and MaxMind disagree", () => {
    const node: NodeDetailOut = {
      ...NODE,
      version: "Satoshi:29.0.0",
      country_code: "DE",
      country_name: "Germany",
      geo_country_code: "FR",
      geo_country_name: "France",
    };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
      />,
    );
    const subtitle = screen.getByTestId("drawer-subtitle").textContent ?? "";
    expect(subtitle).toContain("(MM: France)");
  });

  it("first-seen segment is omitted when first_seen is null", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    expect(screen.queryByTestId("drawer-first-seen")).toBeNull();
    expect(screen.getByTestId("drawer-last-seen").textContent).toContain("2026-04-26");
  });

  it("first-seen segment renders alongside last-seen when present", () => {
    const node: NodeDetailOut = {
      ...NODE,
      first_seen: "2025-11-12T08:30:00Z",
    };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
      />,
    );
    expect(screen.getByTestId("drawer-first-seen").textContent).toContain("2025-11-12");
    expect(screen.getByTestId("drawer-last-seen").textContent).toContain("2026-04-26");
  });

  it("renders a banner card with the raw banner inside a <pre>", () => {
    const node: NodeDetailOut = {
      ...NODE,
      banner: "Bitcoin:\n  User-Agent: /Satoshi:29.3.0/\n  Lastblock: 942053",
    };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
      />,
    );
    const banner = screen.getByTestId("card-banner");
    const pre = screen.getByTestId("banner-pre");
    expect(banner).toBeTruthy();
    expect(pre.tagName).toBe("PRE");
    expect(pre.textContent).toContain("/Satoshi:29.3.0/");
    expect(pre.textContent).toContain("Lastblock: 942053");
  });

  it("does not render a banner card when banner is null", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    expect(screen.queryByTestId("card-banner")).toBeNull();
  });

  it("host card renders only the rows whose source field is non-null", () => {
    const node: NodeDetailOut = {
      ...NODE,
      asn: "AS22773",
      asn_name: "Cox Communications",
      country_name: "United States",
      city: "Reston",
      subdivision: "Virginia",
      geo_country_code: null,
      geo_country_name: null,
      isp: null,
      org: null,
      hostname: null,
      latitude: null,
      longitude: null,
    };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
        initialTab="host"
      />,
    );
    const host = screen.getByTestId("card-host");
    expect(host.textContent).toContain("AS22773");
    expect(host.textContent).toContain("Cox Communications");
    expect(host.textContent).toContain("Reston, Virginia, United States");
    expect(host.querySelector('[data-testid="host-row-isp"]')).toBeNull();
    expect(host.querySelector('[data-testid="host-row-org"]')).toBeNull();
    expect(host.querySelector('[data-testid="host-row-hostname"]')).toBeNull();
    expect(host.querySelector('[data-testid^="host-row-geo-maxmind"]')).toBeNull();
  });

  it("host card renders the empty-state message when every source field is null", () => {
    const node: NodeDetailOut = {
      ...NODE,
      asn: null,
      asn_name: null,
      country_code: null,
      country_name: null,
      city: null,
      subdivision: null,
      geo_country_code: null,
      geo_country_name: null,
      isp: null,
      org: null,
      hostname: null,
      latitude: null,
      longitude: null,
    };
    render(
      <NodeDetailDrawer
        ip={node.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(node)}
        initialTab="host"
      />,
    );
    const host = screen.getByTestId("card-host");
    expect(host.textContent).toContain("· no host metadata available");
  });

  it("third tab is labelled `host`", () => {
    render(
      <NodeDetailDrawer
        ip={NODE.ip}
        onOpenChange={() => {}}
        detailOverride={HOOK_LOADED(NODE)}
      />,
    );
    // The trigger renders a count via tab-count-host; its sibling text is the label
    const trigger = screen.getByTestId("tab-count-host").parentElement;
    expect(trigger?.textContent?.toLowerCase()).toContain("host");
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
