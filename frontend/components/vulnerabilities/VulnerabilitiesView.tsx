"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Glyph } from "@/components/ui/Glyph";
import { Pagination } from "@/components/ui/Pagination";
import { Pill, type CveSeverity } from "@/components/ui/Pill";
import { TableExpandedRow, TableRow } from "@/components/ui/TableRow";
import { useAffectedNodes, useVulnerabilities } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import type { CVEEntryOut } from "@/lib/api/types";

const PAGE_SIZES = [25, 50, 100] as const;
type PageSize = (typeof PAGE_SIZES)[number];
const DEFAULT_PAGE_SIZE: PageSize = 25;

type SortKey = "severity" | "cvss_score" | "published" | "affected_node_count";
type SortDir = "asc" | "desc";

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};
// Anything else (UNKNOWN, NONE, ...) sorts as 0.

const SEVERITY_TO_CVE: Record<string, CveSeverity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

interface ColumnDef {
  key: string;
  label: string;
  sortKey: SortKey | null;
}

const COLUMNS: ColumnDef[] = [
  { key: "severity", label: "SEVERITY", sortKey: "severity" },
  { key: "cve", label: "CVE", sortKey: null },
  { key: "cvss", label: "CVSS", sortKey: "cvss_score" },
  { key: "published", label: "PUBLISHED", sortKey: "published" },
  { key: "affects", label: "AFFECTS", sortKey: null },
  { key: "nodes", label: "NODES", sortKey: "affected_node_count" },
];

// Column track widths kept tight; AFFECTS expands to 1fr.
const GRID_TEMPLATE = "grid-cols-[110px_180px_70px_130px_1fr_70px]";

function compareCVEs(a: CVEEntryOut, b: CVEEntryOut, key: SortKey, dir: SortDir): number {
  const mul = dir === "asc" ? 1 : -1;
  switch (key) {
    case "severity": {
      const av = SEVERITY_RANK[a.severity?.toUpperCase() ?? ""] ?? 0;
      const bv = SEVERITY_RANK[b.severity?.toUpperCase() ?? ""] ?? 0;
      return (av - bv) * mul;
    }
    case "cvss_score": {
      const av = a.cvss_score ?? -1;
      const bv = b.cvss_score ?? -1;
      return (av - bv) * mul;
    }
    case "published": {
      const av = a.published ? Date.parse(a.published) : 0;
      const bv = b.published ? Date.parse(b.published) : 0;
      return (av - bv) * mul;
    }
    case "affected_node_count":
      return (a.affected_node_count - b.affected_node_count) * mul;
  }
}

function severityPill(severity: string): React.ReactNode {
  const norm = severity?.toUpperCase() ?? "";
  const cve = SEVERITY_TO_CVE[norm];
  if (cve) return <Pill kind="CVE" severity={cve} />;
  return <span className="text-meta text-dim uppercase tracking-[0.3px]">{severity || "—"}</span>;
}

function affectedVersionsLabel(av: CVEEntryOut["affected_versions"]): string {
  if (!av || av.length === 0) return "—";
  return av
    .map((v) => {
      if (typeof v === "string") return v;
      if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        return (o.version as string) || JSON.stringify(o);
      }
      return String(v);
    })
    .join(", ");
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function nvdHref(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
}

function HeaderCell({
  col,
  sortBy,
  sortDir,
  onSort,
}: {
  col: ColumnDef;
  sortBy: SortKey;
  sortDir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  if (col.sortKey === null) {
    return (
      <div role="columnheader" className="text-label uppercase text-dim tracking-[0.5px]">
        {col.label}
      </div>
    );
  }
  const active = sortBy === col.sortKey;
  return (
    <div
      role="columnheader"
      aria-sort={active ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        onClick={() => onSort(col.sortKey as SortKey)}
        className={cn(
          "flex items-center text-label uppercase tracking-[0.5px] text-left",
          active ? "text-text" : "text-dim",
        )}
        data-testid={`sort-${col.key}`}
      >
        {col.label}
        {active ? (
          <Glyph
            name="caret"
            className={cn("ml-[4px] text-muted", sortDir === "asc" ? "rotate-180" : "")}
          />
        ) : null}
      </button>
    </div>
  );
}

function AffectedNodesPanel({ cveId }: { cveId: string }) {
  const { affected, error, isLoading } = useAffectedNodes(cveId);

  if (isLoading || !affected) {
    return <span className="text-body-sm text-muted">· loading affected nodes…</span>;
  }
  if (error) {
    return (
      <span role="alert" className="text-body-sm text-alert">
        · failed to load affected nodes
      </span>
    );
  }
  if (affected.nodes.length === 0) {
    return <span className="text-body-sm text-muted">· no nodes currently linked to this CVE</span>;
  }
  return (
    <div className="flex flex-col gap-[6px]" data-testid="affected-nodes-list">
      <div className="text-meta text-muted">
        {affected.total} node{affected.total === 1 ? "" : "s"} affected
      </div>
      <ul className="flex flex-col gap-[2px]">
        {affected.nodes.map((n) => (
          <li key={n.id} className="text-body-sm">
            <Link
              href={`/?ip=${encodeURIComponent(n.ip)}`}
              className="text-text-dim hover:text-text"
              data-testid={`affected-node-${n.ip}`}
            >
              {n.ip}:{n.port}
            </Link>
            <span className="ml-[8px] text-dim">
              {n.version ?? "—"} · {n.country_name ?? "—"} · {n.risk_level ?? "—"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}


export interface VulnerabilitiesViewProps {
  /** Override the SWR result — used for tests. */
  items?: CVEEntryOut[];
  loading?: boolean;
  error?: Error | null;
}

export function VulnerabilitiesView(props: VulnerabilitiesViewProps = {}) {
  const hook = useVulnerabilities();
  const hasInjected = props.items !== undefined;
  const items = hasInjected ? props.items : hook.catalog?.items;
  const isLoading = hasInjected ? false : (props.loading ?? hook.isLoading);
  const error = hasInjected ? null : (props.error ?? hook.error);

  const [sortBy, setSortBy] = useState<SortKey>("affected_node_count");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<PageSize>(DEFAULT_PAGE_SIZE);
  const [expanded, setExpanded] = useState<string | null>(null);

  const sorted = useMemo(() => {
    if (!items) return null;
    const copy = items.slice();
    copy.sort((a, b) => compareCVEs(a, b, sortBy, sortDir));
    return copy;
  }, [items, sortBy, sortDir]);

  const total = sorted?.length ?? 0;
  const pageItems = useMemo(() => {
    if (!sorted) return null;
    const start = (page - 1) * pageSize;
    return sorted.slice(start, start + pageSize);
  }, [sorted, page, pageSize]);

  // Reset to page 1 when sort/pageSize/items change.
  const [resetSig, setResetSig] = useState({ sortBy, sortDir, pageSize, items });
  if (
    resetSig.sortBy !== sortBy ||
    resetSig.sortDir !== sortDir ||
    resetSig.pageSize !== pageSize ||
    resetSig.items !== items
  ) {
    setResetSig({ sortBy, sortDir, pageSize, items });
    setPage(1);
    setExpanded(null);
  }

  function handleSort(key: SortKey) {
    if (sortBy === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir(key === "published" ? "desc" : "desc");
    }
  }

  return (
    <main className="flex-1 min-h-0 flex flex-col" data-testid="vulnerabilities-view">
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

      <div className="flex-1 min-h-0 overflow-y-auto" data-testid="vulnerabilities-body">
        {error ? (
          <TableRow>
            <span role="alert" className="text-body-sm text-alert">
              · CVE catalog failed to load
            </span>
          </TableRow>
        ) : isLoading || !pageItems ? (
          <TableRow>
            <span className="text-body-sm text-muted">· loading CVEs…</span>
          </TableRow>
        ) : pageItems.length === 0 ? (
          <TableRow>
            <span className="text-body-sm text-muted">· no CVEs in the catalog</span>
          </TableRow>
        ) : (
          pageItems.map((e) => {
            const isOpen = expanded === e.cve_id;
            return (
              <div key={e.cve_id}>
                <TableRow
                  onClick={() => setExpanded(isOpen ? null : e.cve_id)}
                  selected={isOpen}
                  className={cn("cursor-pointer", `grid ${GRID_TEMPLATE} gap-[14px]`)}
                  data-testid={`cve-row-${e.cve_id}`}
                >
                  <span className="flex items-center">{severityPill(e.severity)}</span>
                  <span className="flex items-center gap-[6px] text-body-sm">
                    <Glyph
                      name="chevron"
                      className={cn("text-dim", isOpen ? "rotate-90" : "")}
                    />
                    <a
                      href={nvdHref(e.cve_id)}
                      target="_blank"
                      rel="noreferrer"
                      onClick={(ev) => ev.stopPropagation()}
                      className="hover:text-text"
                    >
                      {e.cve_id}
                    </a>
                  </span>
                  <span className="text-body-sm text-text">
                    {e.cvss_score !== null ? e.cvss_score.toFixed(1) : "—"}
                  </span>
                  <span className="text-body-sm text-text-dim">{formatDate(e.published)}</span>
                  <span className="text-body-sm text-text-dim truncate">
                    {affectedVersionsLabel(e.affected_versions)}
                  </span>
                  <span className="text-body-sm text-text">{e.affected_node_count}</span>
                </TableRow>
                {isOpen ? (
                  <TableExpandedRow state={SEVERITY_RANK[e.severity?.toUpperCase() ?? ""] >= 3 ? "alert" : "warn"}>
                    <AffectedNodesPanel cveId={e.cve_id} />
                  </TableExpandedRow>
                ) : null}
              </div>
            );
          })
        )}
      </div>

      {!hasInjected && total > 0 ? (
        <Pagination
          page={page}
          pageSize={pageSize}
          total={total}
          noun="CVEs"
          pageSizes={PAGE_SIZES}
          onPrev={() => setPage((p) => Math.max(1, p - 1))}
          onNext={() => setPage((p) => p + 1)}
          onPageSizeChange={(s) => setPageSize(s as PageSize)}
        />
      ) : null}
    </main>
  );
}
