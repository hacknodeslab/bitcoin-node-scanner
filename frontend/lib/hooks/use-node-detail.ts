"use client";

import useSWR from "swr";
import { getNodeByIp, getNodeGeo } from "../api/endpoints";
import type { NodeGeoOut, NodeOut } from "../api/types";

export interface NodeDetail {
  node: NodeOut;
  geo: NodeGeoOut | null;
}

/**
 * Drawer detail loader. Resolves IP → numeric id via the v0 list-and-scan
 * helper (parity debt: design.md D10 item 1), then fetches `/nodes/{id}/geo`.
 * Returns `null` for `node` when the IP isn't in the database.
 */
async function fetchDetail(ip: string): Promise<NodeDetail | null> {
  const node = await getNodeByIp(ip);
  if (!node) return null;
  const geo = await getNodeGeo(node.id).catch(() => null);
  return { node, geo };
}

export function useNodeDetail(ip: string | null) {
  const { data, error, isLoading } = useSWR<NodeDetail | null>(
    ip ? `/api/v1/nodes/by-ip/${ip}` : null,
    ip ? () => fetchDetail(ip) : null,
  );

  return { detail: data ?? null, error, isLoading };
}
