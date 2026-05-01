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
import { Pill, type CveSeverity } from "@/components/ui/Pill";
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

async function copyToClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
  }
}

/**
 * Node detail drawer (§10). Composes the Drawer primitive with header,
 * tabs (ports / vulnerabilities / refs), three cards, and a footer with
 * the L402 button. Sliver shows recent nodes; clicking a sliver row
 * swaps the active IP without dismissing the drawer.
 */
export function NodeDetailDrawer({
  ip,
  onOpenChange,
  sliverNodes,
  onActivateIp,
  detailOverride,
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
        <div className="flex items-center text-meta text-muted">
          <span>last seen {node?.last_seen ?? "—"}</span>
          {node?.asn ? <span className="mx-[8px] text-dim">·</span> : null}
          {node?.asn ? <span>{node.asn}</span> : null}
          <DrawerCloseButton />
        </div>
        <div className="mt-[6px] flex items-center gap-[8px] text-title">
          <span className="text-text">{node?.ip ?? ip}</span>
          <span className="text-dim">:</span>
          <span
            className={node?.has_exposed_rpc ? "text-alert" : "text-text"}
            data-testid="drawer-port"
          >
            {node?.port ?? "—"}
          </span>
          {node?.is_example ? <Pill kind="EXAMPLE" /> : null}
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
        <div className="mt-[2px] text-meta text-muted">
          {node?.country_name ?? "—"}
          {node?.user_agent ? ` · ${node.user_agent}` : ""}
        </div>
      </div>

      {/* Tabs */}
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
        <Tabs defaultValue="ports" className="flex-1 min-h-0 flex flex-col">
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
            <TabsTrigger value="refs">
              refs
              <span className="ml-[6px] text-dim">0</span>
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

            <TabsContent value="refs">
              <Card data-testid="card-refs">
                <CardLabel>cross-references</CardLabel>
                <CardRow className="text-meta text-muted">
                  · cross-references arrive in a future change
                </CardRow>
              </Card>
            </TabsContent>
          </div>
        </Tabs>
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
