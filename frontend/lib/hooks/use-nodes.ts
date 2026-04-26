"use client";

import useSWR from "swr";
import { listNodes } from "../api/endpoints";
import type { NodeListParams, NodeOut } from "../api/types";

function buildKey(params: NodeListParams): string {
  // Stable key derived from sorted entries — feeds SWR's cache identity.
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null);
  entries.sort(([a], [b]) => a.localeCompare(b));
  const qs = entries.map(([k, v]) => `${k}=${v}`).join("&");
  return `/api/v1/nodes${qs ? "?" + qs : ""}`;
}

export function useNodes(params: NodeListParams = {}) {
  const { data, error, isLoading, mutate } = useSWR<NodeOut[]>(
    buildKey(params),
    () => listNodes(params),
  );

  return { nodes: data, error, isLoading, refresh: mutate };
}
