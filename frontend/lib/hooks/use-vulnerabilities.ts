"use client";

import useSWR from "swr";
import { getVulnerabilities } from "../api/endpoints";
import type { VulnerabilitiesOut } from "../api/types";

/**
 * CVE catalog from `GET /api/v1/vulnerabilities`. The NVD catalog is small,
 * so the page fetches it whole and sorts/paginates client-side.
 */
export function useVulnerabilities() {
  const { data, error, isLoading, mutate } = useSWR<VulnerabilitiesOut>(
    "/api/v1/vulnerabilities",
    () => getVulnerabilities(),
  );

  return { catalog: data, error, isLoading, refresh: mutate };
}
