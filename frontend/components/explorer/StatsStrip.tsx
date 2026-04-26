"use client";

import { useStats } from "@/lib/hooks";
import { StatTile } from "@/components/ui/StatTile";
import type { StatsOut } from "@/lib/api/types";

export interface StatsStripProps {
  /** Override the SWR-driven stats — used for tests and Storybook fixtures. */
  data?: StatsOut;
  /** Render the loading skeleton path even with no hook bindings. */
  loading?: boolean;
  /** Render the error message path. */
  error?: Error | null;
}

interface Tile {
  key: string;
  label: string;
  value: number;
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

function tilesFor(stats: StatsOut): Tile[] {
  return [
    { key: "TOTAL", label: "TOTAL", value: stats.total_nodes },
    { key: "EXPOSED", label: "EXPOSED", value: stats.exposed_count },
    { key: "STALE", label: `STALE >${stats.stale_threshold_days}D`, value: stats.stale_count },
    { key: "TOR", label: "TOR", value: stats.tor_count },
    { key: "OK", label: "OK", value: stats.ok_count },
  ];
}

/**
 * Five-tile strip rendering TOTAL/EXPOSED/STALE/TOR/OK from `/api/v1/stats`.
 *
 * Deltas are intentionally omitted in v0: the backend does not yet emit a
 * baseline (Scan-level snapshots cover total/critical/vulnerable but not
 * exposed/stale/tor/ok). When that arrives, swap to passing
 * `direction: 'rising-bad'` for EXPOSED and `'rising-good'` for OK — the
 * StatTile primitive already supports it.
 */
export function StatsStrip(props: StatsStripProps = {}) {
  const hook = useStats();
  // When `data` is supplied (tests, fixtures), short-circuit the hook entirely
  // so its in-flight loading/error state can't drown out the explicit prop.
  const hasInjectedData = props.data !== undefined;
  const data = hasInjectedData ? props.data : hook.stats;
  const isLoading = hasInjectedData ? false : (props.loading ?? hook.isLoading);
  const error = hasInjectedData ? null : (props.error ?? hook.error);

  if (error) {
    return (
      <div role="alert" className="text-meta text-alert px-[14px] py-[10px]">
        · stats failed to load
      </div>
    );
  }

  if (isLoading || !data) {
    const placeholders = ["TOTAL", "EXPOSED", "STALE", "TOR", "OK"];
    return (
      <div className="grid grid-cols-5 gap-[1px] bg-border" data-testid="stats-strip-loading">
        {placeholders.map((label) => (
          <div key={label} data-testid={`stat-tile-${label}`}>
            <StatTile label={label} value="…" />
          </div>
        ))}
      </div>
    );
  }

  const tiles = tilesFor(data);
  const footer =
    `last scan ${formatTimestamp(data.last_scan_at)}` +
    (data.commit ? ` · build ${data.commit}` : "");
  return (
    <section aria-label="Stats strip">
      <div className="grid grid-cols-5 gap-[1px] bg-border">
        {tiles.map((t) => (
          <div key={t.key} data-testid={`stat-tile-${t.key}`}>
            <StatTile label={t.label} value={t.value} />
          </div>
        ))}
      </div>
      <div className="text-meta text-muted px-[14px] py-[6px]" data-testid="stats-strip-footer">
        {footer}
      </div>
    </section>
  );
}
