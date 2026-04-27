"use client";

import { useState } from "react";
import useSWR from "swr";
import { getScanJob, triggerScan } from "../api/endpoints";
import type { ScanJobOut } from "../api/types";

const TERMINAL = new Set(["completed", "failed"]);

/**
 * Scan-job lifecycle hook.
 *
 *   - `start()`: POSTs to `/api/v1/scans` and returns the new job_id.
 *   - When `jobId` is set, SWR polls `/api/v1/scans/{jobId}` every 10s
 *     until the job reaches a terminal state, then stops.
 *
 * The trigger and the polling are intentionally separate concerns: the
 * caller decides when to start, the hook handles the polling cadence.
 */
export function useScanJob(initialJobId: string | null = null) {
  const [jobId, setJobId] = useState<string | null>(initialJobId);

  const { data, error, isLoading, mutate } = useSWR<ScanJobOut>(
    jobId ? `/api/v1/scans/${jobId}` : null,
    jobId ? () => getScanJob(jobId) : null,
    {
      // Poll every 10s, but stop once the job reaches a terminal state.
      refreshInterval: (latest) =>
        latest && TERMINAL.has(latest.status) ? 0 : 10_000,
      refreshWhenHidden: false,
    },
  );

  async function start(): Promise<ScanJobOut> {
    const created = await triggerScan();
    setJobId(created.job_id);
    return created;
  }

  return { job: data, error, isLoading, jobId, start, refresh: mutate };
}
