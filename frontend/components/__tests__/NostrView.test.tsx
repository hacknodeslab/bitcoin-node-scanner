/**
 * NostrView renders the latest-scan summary cards and a server-paginated
 * relay table. The data hooks are mocked: `useNostrStats` returns a fixed
 * aggregate and `useNostrRelays` returns a fixture while capturing the params
 * it was called with, so we can assert that filters and pagination flow into
 * the request.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";

import { NostrView } from "../nostr/NostrView";
import type { NostrRelayOut, NostrStatsOut } from "@/lib/api/types";

const cap = vi.hoisted(() => ({ lastParams: null as Record<string, unknown> | null }));

const STATS: NostrStatsOut = {
  total: 4,
  resolved: 3,
  behind_any_cdn: 2,
  behind_cdn_pct: 66.7,
  counts: { cloudflare: 1, fastly: 1, direct: 1, dns_error: 1 },
  providers: { cloudflare: 1, fastly: 1 },
  started_at: null,
};

const RELAYS: NostrRelayOut[] = [
  { host: "cf.relay", verdict: "cloudflare", providers: ["cloudflare"], ips: ["104.16.0.1"], error: null, last_seen: null },
  { host: "fast.relay", verdict: "fastly", providers: ["fastly"], ips: ["151.101.1.1"], error: null, last_seen: null },
  { host: "plain.relay", verdict: "direct", providers: [], ips: ["8.8.8.8"], error: null, last_seen: null },
];

vi.mock("@/lib/hooks", async () => {
  const actual = await vi.importActual<typeof import("@/lib/hooks")>("@/lib/hooks");
  return {
    ...actual,
    useNostrStats: () => ({ stats: STATS, error: null, isLoading: false, refresh: () => Promise.resolve(undefined) }),
    useNostrRelays: (params: Record<string, unknown>) => {
      cap.lastParams = params;
      return { relays: RELAYS, total: 120, error: null, isLoading: false };
    },
  };
});

describe("NostrView", () => {
  beforeEach(() => {
    cap.lastParams = null;
  });

  it("renders the centralization summary cards", () => {
    render(<NostrView />);
    const summary = screen.getByTestId("nostr-summary");
    expect(within(summary).getByText("66.7%")).toBeInTheDocument();
    // per-provider breakdown derived from verdict counts
    expect(within(summary).getByText("cloudflare")).toBeInTheDocument();
  });

  it("renders relay rows with a verdict pill", () => {
    render(<NostrView />);
    expect(screen.getByTestId("relay-row-cf.relay")).toBeInTheDocument();
    const row = screen.getByTestId("relay-row-fast.relay");
    expect(within(row).getByText("FASTLY")).toBeInTheDocument();
  });

  it("passes the provider filter into the relay request", () => {
    render(<NostrView />);
    fireEvent.change(screen.getByTestId("filter-provider"), { target: { value: "fastly" } });
    expect(cap.lastParams?.provider).toBe("fastly");
  });

  it("offers verdict options sourced from the scan counts and filters by them", () => {
    render(<NostrView />);
    const verdict = screen.getByTestId("filter-verdict") as HTMLSelectElement;
    // Dropdown only offers verdicts that actually exist in the latest scan.
    const options = Array.from(verdict.options).map((o) => o.value);
    expect(options).toEqual(["", "cloudflare", "direct", "dns_error", "fastly"]);
    fireEvent.change(verdict, { target: { value: "dns_error" } });
    expect(cap.lastParams?.verdict).toBe("dns_error");
  });

  it("passes behind_cdn into the relay request", () => {
    render(<NostrView />);
    fireEvent.click(screen.getByTestId("filter-behind-cdn"));
    expect(cap.lastParams?.behind_cdn).toBe(true);
  });

  it("paginates by advancing the offset", () => {
    render(<NostrView />);
    // default page size 50, total 120 → next page offset should be 50
    fireEvent.click(screen.getByTestId("pagination-next"));
    expect(cap.lastParams?.offset).toBe(50);
  });
});
