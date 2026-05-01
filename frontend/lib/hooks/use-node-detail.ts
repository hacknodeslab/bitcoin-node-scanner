"use client";

import useSWR from "swr";
import { getNodeByIp, getNodeDetail, getNodeGeo } from "../api/endpoints";
import type { NodeDetailOut, NodeGeoOut } from "../api/types";

export interface NodeDetail {
  node: NodeDetailOut;
  geo: NodeGeoOut | null;
}

/**
 * Drawer detail loader. Resolves IP → numeric id via the v0 list-and-scan
 * helper (parity debt: design.md D10 item 1), then fetches `/nodes/{id}` for
 * NVD-derived CVE links and `/nodes/{id}/geo` for MaxMind enrichment.
 * Returns `null` for `node` when the IP isn't in the database.
 */
async function fetchDetail(ip: string): Promise<NodeDetail | null> {
  const stub = await getNodeByIp(ip);
  if (!stub) return null;
  const [node, geo] = await Promise.all([
    getNodeDetail(stub.id),
    getNodeGeo(stub.id).catch(() => null),
  ]);
  return { node, geo };
}

export function useNodeDetail(ip: string | null) {
  const { data, error, isLoading } = useSWR<NodeDetail | null>(
    ip ? `/api/v1/nodes/by-ip/${ip}` : null,
    ip ? () => fetchDetail(ip) : null,
  );

  return { detail: data ?? null, error, isLoading };
}
