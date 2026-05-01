"use client";

import { useMemo, useState } from "react";
import { useNodes } from "@/lib/hooks";
import { Glyph } from "@/components/ui/Glyph";
import { Pill, type CveSeverity } from "@/components/ui/Pill";
import { TableRow } from "@/components/ui/TableRow";
import { cn } from "@/lib/utils";
import type { NodeOut, RiskLevel } from "@/lib/api/types";
import type { ExplorerFilters } from "@/lib/query-grammar";

const PAGE_SIZES = [25, 50, 100] as const;
type PageSize = (typeof PAGE_SIZES)[number];
const DEFAULT_PAGE_SIZE: PageSize = 25;

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
  if (node.is_example) out.push(<Pill key="example" kind="EXAMPLE" />);
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
  selected,
  onSelect,
}: {
  node: NodeOut;
  selected: boolean;
  onSelect: () => void;
}) {
  const portClass = node.has_exposed_rpc ? "text-alert" : "text-text";
  return (
    <TableRow
      onClick={onSelect}
      selected={selected}
      className={cn("cursor-pointer", `grid ${GRID_TEMPLATE} gap-[14px]`)}
      data-example={node.is_example ? "true" : undefined}
      data-testid={`node-row-${node.ip}`}
    >
      <span className="flex items-center gap-[6px] text-body-sm">
        <Glyph name="chevron" className="text-dim" />
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
  /** IP currently shown in the drawer. The matching row gets the selected border. */
  selectedIp?: string | null;
  /** Click on any row → fired with that node's IP. */
  onSelectNode?: (ip: string) => void;
}

interface PaginationProps {
  page: number;
  pageSize: PageSize;
  total: number | null;
  itemsOnPage: number;
  onPrev: () => void;
  onNext: () => void;
  onPageSizeChange: (size: PageSize) => void;
}

function Pagination({
  page,
  pageSize,
  total,
  itemsOnPage,
  onPrev,
  onNext,
  onPageSizeChange,
}: PaginationProps) {
  const offset = (page - 1) * pageSize;
  const totalPages = total !== null ? Math.max(1, Math.ceil(total / pageSize)) : null;
  const prevDisabled = page <= 1;
  const nextDisabled =
    total !== null
      ? offset + itemsOnPage >= total
      : itemsOnPage < pageSize;

  return (
    <div
      data-testid="pagination"
      className="flex items-center gap-[14px] px-[14px] py-[8px] border-t border-border text-meta text-muted"
    >
      <button
        type="button"
        onClick={onPrev}
        disabled={prevDisabled}
        data-testid="pagination-prev"
        className="text-text-dim hover:text-text disabled:text-dim disabled:cursor-not-allowed cursor-pointer"
      >
        ‹ prev
      </button>
      <span data-testid="pagination-status">
        {totalPages !== null
          ? `Page ${page} of ${totalPages} · ${total} results`
          : `Page ${page}`}
      </span>
      <button
        type="button"
        onClick={onNext}
        disabled={nextDisabled}
        data-testid="pagination-next"
        className="text-text-dim hover:text-text disabled:text-dim disabled:cursor-not-allowed cursor-pointer"
      >
        next ›
      </button>
      <span className="ml-auto flex items-center gap-[6px]">
        <span className="text-dim">rows</span>
        <select
          data-testid="pagination-page-size"
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value) as PageSize)}
          className="bg-surface-2 text-text-dim border border-border px-[6px] py-[2px] text-meta cursor-pointer"
        >
          {PAGE_SIZES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </span>
    </div>
  );
}

export function NodeTable(props: NodeTableProps = {}) {
  const [sortBy, setSortBy] = useState<string>(props.initialSortBy ?? "last_seen");
  const [sortDir, setSortDir] = useState<SortDir>(props.initialSortDir ?? "desc");
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<PageSize>(DEFAULT_PAGE_SIZE);

  const filters = props.filters;
  const offset = (page - 1) * pageSize;
  const params = useMemo(
    () => ({
      ...filters,
      sort_by: sortBy,
      sort_dir: sortDir,
      limit: pageSize,
      offset,
    }),
    [filters, sortBy, sortDir, pageSize, offset],
  );
  const hook = useNodes(params);
  const hasInjected = props.nodes !== undefined;
  const nodes = hasInjected ? props.nodes : hook.nodes;
  const total = hasInjected ? null : hook.total;
  const isLoading = hasInjected ? false : (props.loading ?? hook.isLoading);
  const error = hasInjected ? null : (props.error ?? hook.error);

  // Reset to page 1 whenever the inputs that change the result set change.
  // React-recommended "store previous prop in state" pattern instead of an
  // effect — see https://react.dev/learn/you-might-not-need-an-effect.
  const [resetSig, setResetSig] = useState({ filters, sortBy, sortDir, pageSize });
  if (
    resetSig.filters !== filters ||
    resetSig.sortBy !== sortBy ||
    resetSig.sortDir !== sortDir ||
    resetSig.pageSize !== pageSize
  ) {
    setResetSig({ filters, sortBy, sortDir, pageSize });
    setPage(1);
  }

  function handleSort(key: string) {
    if (sortBy === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir("asc");
    }
  }

  return (
    <div data-testid="node-table" className="flex flex-col min-h-0">
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

      <div className="flex-1 min-h-0 overflow-y-auto" data-testid="node-table-body">
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
              selected={props.selectedIp === n.ip}
              onSelect={() => props.onSelectNode?.(n.ip)}
            />
          ))
        )}
      </div>

      {!hasInjected ? (
        <Pagination
          page={page}
          pageSize={pageSize}
          total={total}
          itemsOnPage={nodes?.length ?? 0}
          onPrev={() => setPage((p) => Math.max(1, p - 1))}
          onNext={() => setPage((p) => p + 1)}
          onPageSizeChange={setPageSize}
        />
      ) : null}
    </div>
  );
}
