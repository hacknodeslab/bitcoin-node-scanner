/**
 * VulnerabilitiesView renders the CVE catalog as a sortable table, with each
 * row expandable to show its affected nodes. Catalog data is injected via
 * the `items` prop (same pattern as StatsStrip); the affected-nodes hook is
 * mocked so the expansion path is deterministic.
 */
import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

import { VulnerabilitiesView } from "../vulnerabilities/VulnerabilitiesView";
import type { CVEEntryOut } from "@/lib/api/types";

vi.mock("@/lib/hooks", async () => {
  const actual = await vi.importActual<typeof import("@/lib/hooks")>("@/lib/hooks");
  return {
    ...actual,
    useAffectedNodes: (cveId: string | null) => {
      if (!cveId) return { affected: undefined, error: null, isLoading: false };
      return {
        affected: {
          cve_id: cveId,
          total: 2,
          nodes: [
            {
              id: 1,
              ip: "10.0.0.1",
              port: 8333,
              version: "/Satoshi:25.0/",
              risk_level: "HIGH",
              country_name: "Germany",
              last_seen: null,
            },
            {
              id: 2,
              ip: "10.0.0.2",
              port: 8333,
              version: "/Satoshi:25.0/",
              risk_level: "HIGH",
              country_name: "France",
              last_seen: null,
            },
          ],
        },
        error: null,
        isLoading: false,
      };
    },
    // Keep `useVulnerabilities` from firing an SWR request the test
    // doesn't need (the view reads from injected `items` instead).
    useVulnerabilities: () => ({
      catalog: undefined,
      error: null,
      isLoading: false,
      refresh: () => Promise.resolve(undefined),
    }),
  };
});

const FIXTURE: CVEEntryOut[] = [
  {
    cve_id: "CVE-2023-AAAA",
    published: "2023-01-15T00:00:00Z",
    last_modified: null,
    severity: "MEDIUM",
    cvss_score: 5.5,
    description: null,
    affected_versions: null,
    fetched_at: "2026-01-01T00:00:00Z",
    affected_node_count: 3,
  },
  {
    cve_id: "CVE-2023-BBBB",
    published: "2023-02-15T00:00:00Z",
    last_modified: null,
    severity: "CRITICAL",
    cvss_score: 9.8,
    description: null,
    affected_versions: null,
    fetched_at: "2026-01-01T00:00:00Z",
    affected_node_count: 25,
  },
  {
    cve_id: "CVE-2023-CCCC",
    published: "2023-03-15T00:00:00Z",
    last_modified: null,
    severity: "LOW",
    cvss_score: 2.1,
    description: null,
    affected_versions: null,
    fetched_at: "2026-01-01T00:00:00Z",
    affected_node_count: 0,
  },
];

describe("VulnerabilitiesView", () => {
  it("renders one row per CVE in the catalog", () => {
    render(<VulnerabilitiesView items={FIXTURE} />);
    expect(screen.getByTestId("cve-row-CVE-2023-AAAA")).toBeTruthy();
    expect(screen.getByTestId("cve-row-CVE-2023-BBBB")).toBeTruthy();
    expect(screen.getByTestId("cve-row-CVE-2023-CCCC")).toBeTruthy();
  });

  it("sorts by affected node count descending by default", () => {
    render(<VulnerabilitiesView items={FIXTURE} />);
    const rows = screen.getAllByTestId(/^cve-row-/);
    // BBBB (25) > AAAA (3) > CCCC (0)
    expect(rows[0]).toHaveAttribute("data-testid", "cve-row-CVE-2023-BBBB");
    expect(rows[1]).toHaveAttribute("data-testid", "cve-row-CVE-2023-AAAA");
    expect(rows[2]).toHaveAttribute("data-testid", "cve-row-CVE-2023-CCCC");
  });

  it("renders an empty state when the catalog has no entries", () => {
    render(<VulnerabilitiesView items={[]} />);
    expect(screen.getByText(/no CVEs in the catalog/i)).toBeTruthy();
  });

  it("expanding a row reveals its affected nodes (links into the explorer)", () => {
    render(<VulnerabilitiesView items={FIXTURE} />);
    // Affected-nodes list is hidden before expansion
    expect(screen.queryByTestId("affected-nodes-list")).toBeNull();

    fireEvent.click(screen.getByTestId("cve-row-CVE-2023-BBBB"));

    const list = screen.getByTestId("affected-nodes-list");
    expect(list).toBeTruthy();

    const link = within(list).getByTestId("affected-node-10.0.0.1") as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/?ip=10.0.0.1");
  });
});
