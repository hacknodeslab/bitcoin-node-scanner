"use client";

import useSWR from "swr";
import { getStats } from "../api/endpoints";
import type { StatsOut } from "../api/types";

/**
 * Aggregate stats. Refreshes every 30s while the tab is foreground; SWR's
 * `refreshWhenHidden: false` (default) gates the interval on visibility,
 * so the hook honours the spec's "background tab pauses refresh" rule
 * without manual `document.visibilityState` plumbing.
 */
export function useStats() {
  const { data, error, isLoading, mutate } = useSWR<StatsOut>(
    "/api/v1/stats",
    () => getStats(),
    {
      refreshInterval: 30_000,
      revalidateOnFocus: true,
      refreshWhenHidden: false,
    },
  );

  return { stats: data, error, isLoading, refresh: mutate };
}
