"use client";

import { useMemo, useState } from "react";
import { Pagination } from "@/components/ui/Pagination";
import { Pill } from "@/components/ui/Pill";
import { StatTile } from "@/components/ui/StatTile";
import { TableRow } from "@/components/ui/TableRow";
import { useNostrRelays, useNostrStats } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import type { NostrRelayOut, NostrStatsOut } from "@/lib/api/types";

const PAGE_SIZES = [25, 50, 100] as const;
type PageSize = (typeof PAGE_SIZES)[number];
const DEFAULT_PAGE_SIZE: PageSize = 50;

// CDNs with a public IP list (the only ones the scanner can classify).
const PROVIDERS = ["cloudflare", "cloudfront", "fastly"] as const;

const GRID_TEMPLATE = "grid-cols-[1fr_140px_160px_1fr]";

function SummaryCards({ stats }: { stats: NostrStatsOut }) {
  // Per-provider counts come from the API (`stats.providers`) — no client-side
  // verdict-string parsing.
  const tiles = [
    {
      key: "behind CDN",
      label: "behind CDN",
      value: `${stats.behind_cdn_pct.toFixed(1)}%`,
      hint: `${stats.behind_any_cdn} / ${stats.resolved} resolved`,
    },
    { key: "total hosts", label: "total hosts", value: stats.total },
    { key: "resolved", label: "resolved", value: stats.resolved },
    ...PROVIDERS.map((p) => ({ key: p, label: p, value: stats.providers[p] ?? 0 })),
  ];
  return (
    <div
      className="grid gap-[1px] bg-border border-b border-border md:grid-cols-3 lg:grid-cols-6"
      data-testid="nostr-summary"
    >
      {tiles.map((t) => (
        <div key={t.key} data-testid={`nostr-stat-${t.key}`}>
          <StatTile label={t.label} value={t.value} hint={t.hint} />
        </div>
      ))}
    </div>
  );
}

interface Filters {
  verdict?: string;
  provider?: string;
  behind_cdn?: boolean;
}

function FilterBar({
  filters,
  verdictOptions,
  onChange,
}: {
  filters: Filters;
  /** The verdicts actually present in the latest scan (incl. combos like
   * "cloudflare+fastly"), so the dropdown only offers values that match. */
  verdictOptions: string[];
  onChange: (next: Filters) => void;
}) {
  return (
    <div
      className="flex items-center gap-[12px] px-[14px] py-[8px] border-b border-border text-meta"
      data-testid="nostr-filters"
    >
      <label className="flex items-center gap-[6px]">
        <span className="text-dim uppercase tracking-[0.5px]">provider</span>
        <select
          data-testid="filter-provider"
          value={filters.provider ?? ""}
          onChange={(e) => onChange({ ...filters, provider: e.target.value || undefined })}
          className="bg-surface-2 text-text-dim border border-border px-[6px] py-[2px] text-meta cursor-pointer"
        >
          <option value="">all</option>
          {PROVIDERS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-[6px]">
        <span className="text-dim uppercase tracking-[0.5px]">verdict</span>
        <select
          data-testid="filter-verdict"
          value={filters.verdict ?? ""}
          onChange={(e) => onChange({ ...filters, verdict: e.target.value || undefined })}
          className="bg-surface-2 text-text-dim border border-border px-[6px] py-[2px] text-meta cursor-pointer"
        >
          <option value="">all</option>
          {verdictOptions.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-[6px] cursor-pointer">
        <input
          data-testid="filter-behind-cdn"
          type="checkbox"
          checked={filters.behind_cdn === true}
          onChange={(e) => onChange({ ...filters, behind_cdn: e.target.checked ? true : undefined })}
        />
        <span className="text-dim uppercase tracking-[0.5px]">behind CDN only</span>
      </label>

      {filters.verdict || filters.provider || filters.behind_cdn ? (
        <button
          type="button"
          data-testid="filter-clear"
          onClick={() => onChange({})}
          className="ml-auto text-text-dim hover:text-text cursor-pointer"
        >
          clear
        </button>
      ) : null}
    </div>
  );
}

export interface NostrViewProps {
  /** Override hook data — used for tests. */
  stats?: NostrStatsOut;
  relays?: NostrRelayOut[];
  total?: number;
  loading?: boolean;
  error?: Error | null;
}

export function NostrView(props: NostrViewProps = {}) {
  const injected = props.relays !== undefined;

  const [filters, setFilters] = useState<Filters>({});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<PageSize>(DEFAULT_PAGE_SIZE);

  const statsHook = useNostrStats();
  const relaysHook = useNostrRelays({
    ...filters,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  });

  const stats = injected ? props.stats : statsHook.stats;
  const relays = injected ? props.relays : relaysHook.relays;
  const total = injected ? (props.total ?? props.relays?.length ?? 0) : (relaysHook.total ?? 0);
  const isLoading = injected ? (props.loading ?? false) : relaysHook.isLoading;
  const error = injected ? (props.error ?? null) : relaysHook.error;
  const statsError = injected ? null : statsHook.error;
  const statsLoading = injected ? false : statsHook.isLoading;

  // Reset to page 1 whenever the active filters, page size, or the underlying
  // dataset change — the last guard prevents being stranded on a now-empty
  // page (e.g. "Page 3 of 1") after a smaller scan is imported or revalidated.
  const [resetSig, setResetSig] = useState({ filters, pageSize, total });
  if (
    resetSig.filters !== filters ||
    resetSig.pageSize !== pageSize ||
    resetSig.total !== total
  ) {
    setResetSig({ filters, pageSize, total });
    setPage(1);
  }

  function updateFilters(next: Filters) {
    setFilters(next);
  }

  const noScan =
    !isLoading && !statsLoading && !error && stats !== undefined && stats.total === 0;

  // Verdict options come straight from the scan's counts, so the dropdown only
  // offers values that exist (including combos) — picking one always matches.
  const verdictOptions = useMemo(
    () => (stats ? Object.keys(stats.counts).sort() : []),
    [stats],
  );

  return (
    <main className="flex-1 min-h-0 flex flex-col" data-testid="nostr-view">
      {statsError ? (
        <div
          role="alert"
          data-testid="nostr-stats-error"
          className="px-[14px] py-[8px] border-b border-border text-body-sm text-alert"
        >
          · stats failed to load
        </div>
      ) : !noScan && stats ? (
        // Skip the summary on the no-scan state — its zeroed tiles would sit
        // misleadingly above the "no scan imported" message.
        <SummaryCards stats={stats} />
      ) : null}

      {noScan ? (
        <div className="flex-1 flex items-center justify-center text-body-sm text-muted" data-testid="nostr-empty">
          · no Nostr scan imported yet — run the scanner and load it with{" "}
          <code className="mx-[4px] text-text-dim">db-import-nostr</code>
        </div>
      ) : (
        <>
          <FilterBar filters={filters} verdictOptions={verdictOptions} onChange={updateFilters} />

          <div
            className={cn("grid gap-[14px] px-[14px] py-[9px] border-b border-border", GRID_TEMPLATE)}
          >
            <div className="text-label uppercase text-dim tracking-[0.5px]">HOST</div>
            <div className="text-label uppercase text-dim tracking-[0.5px]">VERDICT</div>
            <div className="text-label uppercase text-dim tracking-[0.5px]">PROVIDERS</div>
            <div className="text-label uppercase text-dim tracking-[0.5px]">IPS</div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto" data-testid="nostr-body">
            {error ? (
              <TableRow>
                <span role="alert" className="text-body-sm text-alert">
                  · relay list failed to load
                </span>
              </TableRow>
            ) : isLoading || (stats === undefined && !statsError) || !relays ? (
              <TableRow>
                <span className="text-body-sm text-muted">· loading relays…</span>
              </TableRow>
            ) : relays.length === 0 ? (
              <TableRow>
                <span className="text-body-sm text-muted">· no relays match these filters</span>
              </TableRow>
            ) : (
              relays.map((r) => (
                <TableRow
                  key={r.host}
                  className={cn("grid gap-[14px]", GRID_TEMPLATE)}
                  data-testid={`relay-row-${r.host}`}
                >
                  <span className="text-body-sm text-text truncate" title={r.host}>
                    {r.host}
                  </span>
                  <span className="flex items-center">
                    <Pill kind="CDN" verdict={r.verdict} />
                  </span>
                  <span className="text-body-sm text-text-dim truncate">
                    {r.providers.length ? r.providers.join(", ") : "—"}
                  </span>
                  <span className="text-body-sm text-text-dim truncate" title={r.ips.join(", ")}>
                    {r.ips.length ? r.ips.join(", ") : r.error ?? "—"}
                  </span>
                </TableRow>
              ))
            )}
          </div>

          {!injected && total > 0 ? (
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              noun="relays"
              pageSizes={PAGE_SIZES}
              onPrev={() => setPage((p) => Math.max(1, p - 1))}
              onNext={() => setPage((p) => p + 1)}
              onPageSizeChange={(s) => setPageSize(s as PageSize)}
            />
          ) : null}
        </>
      )}
    </main>
  );
}
