"use client";

import useSWR from "swr";
import { getAffectedNodes } from "../api/endpoints";
import type { AffectedNodesOut } from "../api/types";

/**
 * Nodes affected by a CVE (`GET /api/v1/vulnerabilities/{cve_id}/nodes`).
 * Pass `null` to skip the fetch — used so the vulnerabilities table only
 * loads affected nodes for the row the operator actually expands.
 */
export function useAffectedNodes(cveId: string | null) {
  const { data, error, isLoading } = useSWR<AffectedNodesOut>(
    cveId ? `/api/v1/vulnerabilities/${cveId}/nodes` : null,
    () => getAffectedNodes(cveId as string),
  );

  return { affected: data, error, isLoading };
}
