"use client";

import useSWR from "swr";
import { getNostrRelays } from "../api/endpoints";
import type { NostrRelayListParams, NostrRelayOut } from "../api/types";

interface NostrRelaysResult {
  relays: NostrRelayOut[];
  total: number | null;
}

/**
 * Paginated relay list for the Nostr panel. Filtering and pagination are
 * server-side (the relay set can exceed 1000 hosts), so params are part of
 * the SWR key.
 */
export function useNostrRelays(params: NostrRelayListParams = {}) {
  const key = ["/api/v1/nostr/relays", JSON.stringify(params)] as const;
  const { data, error, isLoading } = useSWR<NostrRelaysResult>(key, () =>
    getNostrRelays(params),
  );

  return {
    relays: data?.relays,
    total: data?.total ?? null,
    error,
    isLoading,
  };
}
