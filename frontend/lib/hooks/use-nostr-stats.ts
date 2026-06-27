"use client";

import useSWR from "swr";
import { getNostrStats } from "../api/endpoints";
import type { NostrStatsOut } from "../api/types";

/**
 * Aggregates for the latest Nostr CDN-recon scan from `GET /api/v1/nostr/stats`.
 * Returns zeroed values when no scan has been imported.
 */
export function useNostrStats() {
  const { data, error, isLoading, mutate } = useSWR<NostrStatsOut>(
    "/api/v1/nostr/stats",
    () => getNostrStats(),
  );

  return { stats: data, error, isLoading, refresh: mutate };
}
