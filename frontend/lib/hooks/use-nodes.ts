"use client";

import useSWR from "swr";
import { listNodesWithTotal } from "../api/endpoints";
import type { NodeListParams, NodeOut } from "../api/types";

function buildKey(params: NodeListParams): string {
  // Stable key derived from sorted entries — feeds SWR's cache identity.
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null);
  entries.sort(([a], [b]) => a.localeCompare(b));
  const qs = entries.map(([k, v]) => `${k}=${v}`).join("&");
  return `/api/v1/nodes${qs ? "?" + qs : ""}`;
}

interface UseNodesData {
  nodes: NodeOut[];
  total: number | null;
}

export function useNodes(params: NodeListParams = {}) {
  const { data, error, isLoading, mutate } = useSWR<UseNodesData>(
    buildKey(params),
    () => listNodesWithTotal(params),
  );

  return {
    nodes: data?.nodes,
    total: data?.total ?? null,
    error,
    isLoading,
    refresh: mutate,
  };
}
