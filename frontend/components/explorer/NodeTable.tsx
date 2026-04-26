"use client";

import { useMemo, useState } from "react";
import { useNodes } from "@/lib/hooks";
import { Glyph } from "@/components/ui/Glyph";
import { Pill, type CveSeverity } from "@/components/ui/Pill";
import { TableRow, TableExpandedRow } from "@/components/ui/TableRow";
import { cn } from "@/lib/utils";
import type { NodeOut, RiskLevel } from "@/lib/api/types";
import type { ExplorerFilters } from "@/lib/query-grammar";

/**
 * STALE threshold mirrored from the backend default. The /api/v1/stats
 * endpoint exposes the real value (`stale_threshold_days`); this constant
 * keeps the per-row pill consistent with the strip's count without making
 * NodeTable depend on the stats fetch. If/when the backend gate becomes
 * configurable per-deployment, swap to a context provider that reads stats.
 */
const STALE_THRESHOLD_DAYS = 7;

interface ColumnDef {
  key: string;
  label: string;
  sortKey: string | null; // null → not sortable
  width: string; // tailwind grid-column track
}

const COLUMNS: ColumnDef[] = [
  { key: "ip", label: "IP", sortKey: "ip", width: "180px" },
  { key: "port", label: "PORT", sortKey: "port", width: "60px" },
  { key: "version", label: "VERSION", sortKey: "version", width: "180px" },
  { key: "country", label: "CC", sortKey: "country_name", width: "40px" },
  { key: "risk", label: "RISK", sortKey: "risk_level", width: "80px" },
  { key: "flags", label: "FLAGS", sortKey: null, width: "1fr" },
];

const GRID_TEMPLATE = `grid-cols-[180px_60px_180px_40px_80px_1fr]`;
type SortDir = "asc" | "desc";

const RISK_TO_STATE: Record<RiskLevel, "alert" | "warn" | "ok"> = {
  CRITICAL: "alert",
  HIGH: "alert",
  MEDIUM: "warn",
  LOW: "ok",
};

const RISK_TO_CVE_SEVERITY: Record<RiskLevel, CveSeverity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

function isStale(lastSeen: string | null): boolean {
  if (!lastSeen) return false;
  const t = new Date(lastSeen).getTime();
  if (Number.isNaN(t)) return false;
  const ageMs = Date.now() - t;
  return ageMs > STALE_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
}

function isTorNode(node: NodeOut): boolean {
  if (node.hostname && node.hostname.endsWith(".onion")) return true;
  return Array.isArray(node.tags) && node.tags.some((t) => t.toLowerCase() === "tor");
}

function pillsFor(node: NodeOut) {
  const out: React.ReactNode[] = [];
  if (node.has_exposed_rpc) out.push(<Pill key="exposed" kind="EXPOSED" />);
  if (isStale(node.last_seen)) out.push(<Pill key="stale" kind="STALE" />);
  if (isTorNode(node)) out.push(<Pill key="tor" kind="TOR" />);
  if (node.is_vulnerable && node.risk_level) {
    out.push(
      <Pill key="cve" kind="CVE" severity={RISK_TO_CVE_SEVERITY[node.risk_level]} />,
    );
  }
  return out;
}

function SortIndicator({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return null;
  return (
    <Glyph
      name="caret"
      className={cn("ml-[4px] text-muted", dir === "asc" ? "rotate-180" : "")}
    />
  );
}

interface HeaderCellProps {
  col: ColumnDef;
  sortBy: string | null;
  sortDir: SortDir;
  onSort: (key: string) => void;
}

function HeaderCell({ col, sortBy, sortDir, onSort }: HeaderCellProps) {
  const sortable = col.sortKey !== null;
  const active = sortable && sortBy === col.sortKey;
  if (!sortable) {
    return (
      <div role="columnheader" className="text-label uppercase text-dim tracking-[0.5px]">
        {col.label}
      </div>
    );
  }
  return (
    <div
      role="columnheader"
      aria-sort={active ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={() => onSort(col.sortKey!)}
        className={cn(
          "flex items-center text-label uppercase tracking-[0.5px] text-left",
          active ? "text-text" : "text-dim",
        )}
        data-testid={`sort-${col.key}`}
      >
        {col.label}
        <SortIndicator active={active} dir={sortDir} />
      </button>
    </div>
  );
}

function NodeRow({
  node,
  expanded,
  onToggle,
}: {
  node: NodeOut;
  expanded: boolean;
  onToggle: () => void;
}) {
  const portClass = node.has_exposed_rpc ? "text-alert" : "text-text";
  return (
    <>
      <TableRow
        onClick={onToggle}
        className={cn("cursor-pointer", `grid ${GRID_TEMPLATE} gap-[14px]`)}
        data-testid={`node-row-${node.ip}`}
      >
        <span className="flex items-center gap-[6px] text-body-sm">
          <Glyph
            name="chevron"
            className={cn("text-dim", expanded ? "rotate-90" : "")}
          />
          {node.ip}
        </span>
        <span className={cn("text-body-sm", portClass)}>{node.port}</span>
        <span className="text-body-sm text-text-dim truncate">
          {node.version ?? "—"}
        </span>
        <span className="text-body-sm text-muted">{node.country_code ?? "—"}</span>
        <span className="text-body-sm text-text">{node.risk_level ?? "—"}</span>
        <span className="flex flex-wrap gap-[4px]">{pillsFor(node)}</span>
      </TableRow>
      {expanded ? (
        <TableExpandedRow state={node.risk_level ? RISK_TO_STATE[node.risk_level] : "dim"}>
          <div className="grid grid-cols-2 gap-x-[24px] gap-y-[4px]">
            <div>
              <span className="text-dim">hostname </span>
              <span className="text-text">{node.hostname ?? "—"}</span>
            </div>
            <div>
              <span className="text-dim">last seen </span>
              <span className="text-text">{node.last_seen ?? "—"}</span>
            </div>
            <div>
              <span className="text-dim">asn </span>
              <span className="text-text">{node.asn ?? "—"}</span>
            </div>
            <div>
              <span className="text-dim">country </span>
              <span className="text-text">{node.country_name ?? "—"}</span>
            </div>
            <div>
              <span className="text-dim">user-agent </span>
              <span className="text-text">{node.user_agent ?? "—"}</span>
            </div>
            <div>
              <span className="text-dim">tags </span>
              <span className="text-text">
                {node.tags && node.tags.length > 0 ? node.tags.join(", ") : "—"}
              </span>
            </div>
          </div>
        </TableExpandedRow>
      ) : null}
    </>
  );
}

export interface NodeTableProps {
  /** Override the SWR result — used for tests. */
  nodes?: NodeOut[];
  loading?: boolean;
  error?: Error | null;
  /** Initial sort column; defaults to last_seen desc. */
  initialSortBy?: string;
  initialSortDir?: SortDir;
  /** Filters lifted from the QueryBarController — merged into the useNodes params. */
  filters?: ExplorerFilters;
}

export function NodeTable(props: NodeTableProps = {}) {
  const [sortBy, setSortBy] = useState<string>(props.initialSortBy ?? "last_seen");
  const [sortDir, setSortDir] = useState<SortDir>(props.initialSortDir ?? "desc");
  const [expanded, setExpanded] = useState<string | null>(null);

  const filters = props.filters;
  const params = useMemo(
    () => ({ ...filters, sort_by: sortBy, sort_dir: sortDir, limit: 100 }),
    [filters, sortBy, sortDir],
  );
  const hook = useNodes(params);
  const hasInjected = props.nodes !== undefined;
  const nodes = hasInjected ? props.nodes : hook.nodes;
  const isLoading = hasInjected ? false : (props.loading ?? hook.isLoading);
  const error = hasInjected ? null : (props.error ?? hook.error);

  function handleSort(key: string) {
    if (sortBy === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir("asc");
    }
  }

  return (
    <div data-testid="node-table">
      <div
        className={cn(
          "grid gap-[14px] px-[14px] py-[9px] border-b border-border",
          GRID_TEMPLATE,
        )}
      >
        {COLUMNS.map((col) => (
          <HeaderCell
            key={col.key}
            col={col}
            sortBy={sortBy}
            sortDir={sortDir}
            onSort={handleSort}
          />
        ))}
      </div>

      {error ? (
        <TableRow>
          <span role="alert" className="text-body-sm text-alert">
            · nodes failed to load
          </span>
        </TableRow>
      ) : isLoading || !nodes ? (
        <TableRow>
          <span className="text-body-sm text-muted">· loading nodes…</span>
        </TableRow>
      ) : nodes.length === 0 ? (
        <TableRow>
          <span className="text-body-sm text-muted">· no nodes match the current filters</span>
        </TableRow>
      ) : (
        nodes.map((n) => (
          <NodeRow
            key={n.id}
            node={n}
            expanded={expanded === n.ip}
            onToggle={() => setExpanded((cur) => (cur === n.ip ? null : n.ip))}
          />
        ))
      )}
    </div>
  );
}
