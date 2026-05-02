"use client";

import { useState } from "react";
import {
  Drawer,
  DrawerCloseButton,
  DrawerTitle,
  DrawerDescription,
  type DrawerSliverItem,
} from "@/components/ui/Drawer";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/Tabs";
import { Card, CardLabel, CardRow } from "@/components/ui/Card";
import { Pill, type CveSeverity, type PillKind } from "@/components/ui/Pill";
import { Button } from "@/components/ui/Button";
import { useNodeDetail } from "@/lib/hooks";
import { fetchL402Example } from "@/lib/api/endpoints";
import { cn } from "@/lib/utils";
import type { NodeOut } from "@/lib/api/types";

function severityToCveSeverity(severity: string | null | undefined): CveSeverity {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    default:
      return "low";
  }
}

function tagsToPillProps(tags: string[] | null | undefined): PillKind[] {
  if (!Array.isArray(tags)) return [];
  return tags
    .map((raw): PillKind | null => {
      const t = raw?.toLowerCase().trim();
      if (!t) return null;
      if (t === "tor") return { kind: "TOR" };
      if (t === "bitcoin") return { kind: "BITCOIN" };
      return { kind: "TAG", label: t };
    })
    .filter((p): p is PillKind => p !== null);
}

function formatTimestamp(value: string | null | undefined): string | null {
  if (!value) return null;
  // Trim ISO timestamp to YYYY-MM-DD when possible; leave as-is if not parseable.
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toISOString().slice(0, 10);
}

function composeLocality(
  city: string | null | undefined,
  subdivision: string | null | undefined,
  country: string | null | undefined,
): string | null {
  const parts = [city, subdivision, country].filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  return parts.length > 0 ? parts.join(", ") : null;
}

function composeSubtitle(node: {
  version?: string | null;
  city?: string | null;
  subdivision?: string | null;
  country_name?: string | null;
  country_code?: string | null;
  geo_country_code?: string | null;
  geo_country_name?: string | null;
}): string | null {
  const segments: string[] = [];
  if (node.version) segments.push(node.version);
  const locality = composeLocality(node.city, node.subdivision, node.country_name);
  if (locality) segments.push(locality);
  if (
    node.geo_country_code &&
    node.country_code &&
    node.geo_country_code !== node.country_code &&
    node.geo_country_name
  ) {
    segments.push(`(MM: ${node.geo_country_name})`);
  }
  return segments.length > 0 ? segments.join(" · ") : null;
}

interface OpenPort {
  port?: number;
  product?: string;
  service?: string;
}

function asOpenPorts(value: unknown[] | null | undefined): OpenPort[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => (typeof v === "object" && v !== null ? (v as OpenPort) : null))
    .filter((v): v is OpenPort => v !== null);
}

interface HostMetadataRow {
  key: string;
  value: string;
}

function buildHostMetadataRows(node: {
  asn?: string | null;
  asn_name?: string | null;
  isp?: string | null;
  org?: string | null;
  hostname?: string | null;
  city?: string | null;
  subdivision?: string | null;
  country_name?: string | null;
  geo_country_code?: string | null;
  geo_country_name?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}): HostMetadataRow[] {
  const rows: HostMetadataRow[] = [];
  if (node.asn) {
    rows.push({
      key: "ASN",
      value: node.asn_name ? `${node.asn} ${node.asn_name}` : node.asn,
    });
  }
  if (node.isp) rows.push({ key: "ISP", value: node.isp });
  if (node.org) rows.push({ key: "ORG", value: node.org });
  if (node.hostname) rows.push({ key: "HOSTNAME", value: node.hostname });
  const shodanGeo = composeLocality(node.city, node.subdivision, node.country_name);
  if (shodanGeo) rows.push({ key: "GEO (Shodan)", value: shodanGeo });
  if (node.geo_country_code && node.geo_country_name) {
    rows.push({ key: "GEO (MaxMind)", value: node.geo_country_name });
  }
  if (typeof node.latitude === "number" && typeof node.longitude === "number") {
    rows.push({
      key: "LAT/LON",
      value: `${node.latitude.toFixed(4)}, ${node.longitude.toFixed(4)}`,
    });
  }
  return rows;
}

async function copyToClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
  }
}

export interface NodeDetailDrawerProps {
  /** When `null`, the drawer is closed. Setting an IP opens it. */
  ip: string | null;
  onOpenChange: (open: boolean) => void;
  /** Sliver list — the recently-seen nodes to enable in-place swapping. */
  sliverNodes?: NodeOut[];
  /** Click on a sliver row swaps the active IP without dismissing. */
  onActivateIp?: (ip: string) => void;
  /** Override useNodeDetail for fixtures/tests. */
  detailOverride?: ReturnType<typeof useNodeDetail>;
  /** Test escape hatch — pin the initially active tab. Production uses `ports`. */
  initialTab?: "ports" | "vulnerabilities" | "host";
}

/**
 * Node detail drawer (§10). Composes the Drawer primitive with header,
 * banner card, tabs (ports / vulnerabilities / host), and a footer with
 * the L402 button. Sliver shows recent nodes; clicking a sliver row
 * swaps the active IP without dismissing the drawer.
 */
export function NodeDetailDrawer({
  ip,
  onOpenChange,
  sliverNodes,
  onActivateIp,
  detailOverride,
  initialTab = "ports",
}: NodeDetailDrawerProps) {
  const liveDetail = useNodeDetail(ip);
  const detail = detailOverride ?? liveDetail;

  const [l402Note, setL402Note] = useState<string | null>(null);

  const sliverItems: DrawerSliverItem[] | undefined = sliverNodes?.map((n) => ({
    id: String(n.id),
    label: n.ip,
    active: n.ip === ip,
    onActivate: () => onActivateIp?.(n.ip),
  }));

  async function handleL402Click() {
    setL402Note(null);
    try {
      const r = await fetchL402Example();
      if (r.kind === "l402-challenge") {
        setL402Note("· l402 not yet available");
      } else {
        setL402Note("· l402 demo OK");
      }
    } catch {
      setL402Note("· l402 fetch failed");
    }
  }

  const node = detail.detail?.node;
  const open = ip !== null;

  // Counts (computed even when node is missing — defaults to 0).
  // `cves` are the NVD-derived links from `node_vulnerabilities`; we filter
  // out resolved entries so the badge reflects only what is currently active.
  const openPorts = asOpenPorts(node?.open_ports);
  const cveList = (node?.cves ?? []).filter((c) => c.resolved_at === null);
  const portCount = openPorts.length;
  const cveCount = cveList.length;

  const subtitle = node ? composeSubtitle(node) : null;
  const tagPills = tagsToPillProps(node?.tags);
  const hostRows = node ? buildHostMetadataRows(node) : [];
  const lastSeen = formatTimestamp(node?.last_seen);
  const firstSeen = formatTimestamp(node?.first_seen);

  return (
    <Drawer
      open={open}
      onOpenChange={onOpenChange}
      sliverItems={sliverItems}
      sliverLabel="RECENT"
    >
      <DrawerTitle className="sr-only">Node detail {ip ?? ""}</DrawerTitle>
      <DrawerDescription className="sr-only">
        Inspect the selected node. Switch nodes via the sliver. Press Esc to close.
      </DrawerDescription>

      {/* Header */}
      <div
        className="px-[16px] py-[12px] border-b border-border"
        data-testid="drawer-header"
        data-example={node?.is_example ? "true" : undefined}
      >
        {/* Line 1 — meta row */}
        <div className="flex items-center text-meta text-muted">
          <span data-testid="drawer-last-seen">seen {lastSeen ?? "—"}</span>
          {firstSeen ? (
            <>
              <span className="mx-[8px] text-dim">·</span>
              <span data-testid="drawer-first-seen">since {firstSeen}</span>
            </>
          ) : null}
          {node?.asn ? (
            <>
              <span className="mx-[8px] text-dim">·</span>
              <span>
                {node.asn}
                {node.asn_name ? ` ${node.asn_name}` : ""}
              </span>
            </>
          ) : null}
          <DrawerCloseButton />
        </div>

        {/* Line 2 — IP:port + pill row */}
        <div className="mt-[6px] flex flex-wrap items-center gap-[8px] text-title">
          <span className="text-text">{node?.ip ?? ip}</span>
          <span className="text-dim">:</span>
          <span
            className={node?.has_exposed_rpc ? "text-alert" : "text-text"}
            data-testid="drawer-port"
          >
            {node?.port ?? "—"}
          </span>
          {node?.is_example ? <Pill kind="EXAMPLE" /> : null}
          {node?.is_dev_version ? <Pill kind="DEV" /> : null}
          {node?.risk_level ? (
            <Pill kind="RISK" severity={severityToCveSeverity(node.risk_level)} />
          ) : null}
          {tagPills.map((p, i) => (
            <Pill key={`${p.kind}-${i}`} {...p} />
          ))}
          {node ? (
            <button
              type="button"
              onClick={() => copyToClipboard(node.ip)}
              className="ml-[8px] text-meta text-muted hover:text-text"
              data-testid="drawer-copy-ip"
              aria-label="Copy IP"
            >
              copy
            </button>
          ) : null}
        </div>

        {/* Line 3 — subtitle (version · locality · MaxMind divergence) */}
        {subtitle ? (
          <div
            className="mt-[2px] text-meta text-muted"
            data-testid="drawer-subtitle"
          >
            {subtitle}
          </div>
        ) : null}
      </div>

      {/* Body */}
      {detail.isLoading ? (
        <div className="px-[16px] py-[12px] text-meta text-muted">· loading detail…</div>
      ) : detail.error ? (
        <div role="alert" className="px-[16px] py-[12px] text-meta text-alert">
          · failed to load detail
        </div>
      ) : !node ? (
        <div className="px-[16px] py-[12px] text-meta text-muted">
          · node not found in the database
        </div>
      ) : (
        <>
          {/* Banner card — always visible above the tabs when populated */}
          {node.banner ? (
            <div className="px-[16px] pt-[12px]">
              <Card data-testid="card-banner">
                <CardLabel>banner</CardLabel>
                <pre
                  data-testid="banner-pre"
                  className="font-mono text-body-sm whitespace-pre-wrap max-h-[180px] overflow-y-auto px-[12px] py-[8px]"
                >
                  {node.banner}
                </pre>
              </Card>
            </div>
          ) : null}

          <Tabs defaultValue={initialTab} className="flex-1 min-h-0 flex flex-col">
            <TabsList>
              <TabsTrigger value="ports">
                ports
                <span className="ml-[6px] text-dim" data-testid="tab-count-ports">
                  {portCount}
                </span>
              </TabsTrigger>
              <TabsTrigger value="vulnerabilities">
                vulnerabilities
                <span
                  className={cn("ml-[6px]", cveCount > 0 ? "text-alert" : "text-dim")}
                  data-testid="tab-count-vulns"
                >
                  {cveCount}
                </span>
              </TabsTrigger>
              <TabsTrigger value="host">
                host
                <span className="ml-[6px] text-dim" data-testid="tab-count-host">
                  {hostRows.length}
                </span>
              </TabsTrigger>
            </TabsList>

            <div className="flex-1 min-h-0 overflow-y-auto p-[16px]">
              <TabsContent value="ports">
                <Card data-testid="card-ports">
                  <CardLabel>open ports</CardLabel>
                  {openPorts.length === 0 ? (
                    <CardRow className="text-meta text-muted">· no open ports recorded</CardRow>
                  ) : (
                    <div className="grid grid-cols-3 gap-[1px] bg-border-dim">
                      {openPorts.map((p, i) => (
                        <div key={i} className="bg-surface px-[12px] py-[8px] text-body-sm">
                          <span className="text-text">{p.port ?? "—"}</span>
                          {p.service ? (
                            <span className="text-muted ml-[6px]">{p.service}</span>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              </TabsContent>

              <TabsContent value="vulnerabilities">
                <Card data-testid="card-vulns">
                  <CardLabel>cves</CardLabel>
                  {cveList.length === 0 ? (
                    <CardRow className="text-meta text-muted">· no vulnerabilities recorded</CardRow>
                  ) : (
                    <div className="px-[12px] py-[8px] flex flex-wrap gap-[6px]">
                      {cveList.map((cve) => (
                        <span key={cve.cve_id} className="flex items-center gap-[6px]">
                          <Pill kind="CVE" severity={severityToCveSeverity(cve.severity)} />
                          <span className="text-meta text-muted">{cve.cve_id}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </Card>
              </TabsContent>

              <TabsContent value="host">
                <Card data-testid="card-host">
                  <CardLabel>host metadata</CardLabel>
                  {hostRows.length === 0 ? (
                    <CardRow className="text-meta text-muted">· no host metadata available</CardRow>
                  ) : (
                    <div className="flex flex-col">
                      {hostRows.map((row, i) => (
                        <div
                          key={row.key}
                          className={cn(
                            "flex items-baseline gap-[12px] px-[12px] py-[6px] text-body-sm",
                            i < hostRows.length - 1 ? "border-b border-border-dim" : "",
                          )}
                          data-testid={`host-row-${row.key.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}
                        >
                          <span className="text-muted text-meta uppercase tracking-[0.3px] w-[120px] shrink-0">
                            {row.key}
                          </span>
                          <span className="text-text-dim break-all">{row.value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              </TabsContent>
            </div>
          </Tabs>
        </>
      )}

      {/* Footer */}
      <div
        className="flex items-center gap-[12px] px-[16px] py-[10px] border-t border-border"
        data-testid="drawer-footer"
      >
        {l402Note ? (
          <span
            className="text-meta text-warn"
            data-testid="drawer-l402-note"
            role="status"
          >
            {l402Note}
          </span>
        ) : null}
        <span className="ml-auto" />
        <Button
          variant="l402"
          type="button"
          onClick={handleL402Click}
          data-testid="drawer-l402-button"
        >
          unlock with l402
        </Button>
      </div>
    </Drawer>
  );
}
