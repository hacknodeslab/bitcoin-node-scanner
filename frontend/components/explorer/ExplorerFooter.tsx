"use client";

import { useState } from "react";
import { mutate } from "swr";
import { Glyph } from "@/components/ui/Glyph";
import { Button } from "@/components/ui/Button";
import { useScanJob } from "@/lib/hooks";
import type { ScanJobOut } from "@/lib/api/types";

export interface ExplorerFooterProps {
  /** Override the scan-job hook for tests/fixtures. */
  job?: ScanJobOut | null;
  /** Override the start handler — receives the test's stub. */
  onStart?: () => void | Promise<void>;
  /** Force the disabled-while-running state in stories without a real fetch. */
  busyOverride?: boolean;
}

const TERMINAL = new Set<string>(["completed", "failed"]);

function statusToneClass(status: string | null | undefined): string {
  switch (status) {
    case "pending":
      return "text-warn";
    case "running":
      return "text-text";
    case "completed":
      return "text-ok";
    case "failed":
      return "text-alert";
    default:
      return "text-dim";
  }
}

function statusLabel(status: string | null | undefined): string {
  switch (status) {
    case "pending":
      return "queued";
    case "running":
      return "scanning…";
    case "completed":
      return "done";
    case "failed":
      return "failed";
    default:
      return "idle";
  }
}

/**
 * Footer strip with kbd hints on the left and the scan trigger on the right.
 *
 * Lifecycle:
 *   - idle → click "run scan" → start() → SWR begins polling /scans/{id}
 *     every 10s (handled by useScanJob).
 *   - while pending/running: button disabled, status text shows status.
 *   - on completion: refresh /api/v1/stats + every /api/v1/nodes key so the
 *     strip + table reflect the new data without a manual reload.
 *   - on failure: button re-enables; status stays "failed" with the API
 *     error surfaced inline.
 */
export function ExplorerFooter(props: ExplorerFooterProps = {}) {
  const hook = useScanJob();
  const job = props.job ?? hook.job ?? null;
  const start = props.onStart ?? hook.start;
  const [startError, setStartError] = useState<string | null>(null);

  const status = job?.status ?? null;
  const isBusy = props.busyOverride ?? (status === "pending" || status === "running");

  // Render-time refresh on terminal-status transition. Pure-state pattern so
  // we don't need an effect for what is really a derived signal.
  const [lastTerminalSeen, setLastTerminalSeen] = useState<string | null>(null);
  if (status && TERMINAL.has(status) && status !== lastTerminalSeen) {
    setLastTerminalSeen(status);
    if (status === "completed") {
      mutate("/api/v1/stats");
      mutate((key) => typeof key === "string" && key.startsWith("/api/v1/nodes"));
    }
  }

  async function handleClick() {
    setStartError(null);
    try {
      await start();
    } catch (e) {
      setStartError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <footer
      className="border-t border-border text-meta text-muted"
      data-testid="explorer-footer"
    >
      {/* Top row: kbd hints + scan status/trigger. */}
      <div className="flex items-center gap-[14px] px-[14px] py-[8px]" data-testid="footer-actions">
        <span className="flex items-center gap-[4px]">
          <span className="text-dim">/</span>
          <span>focus query</span>
        </span>
        <Glyph name="sep" className="text-dim" />
        <span className="flex items-center gap-[4px]">
          <Glyph name="cmd" />
          <span>K</span>
          <span>palette</span>
        </span>

        {status ? (
          <span
            data-testid="scan-status"
            className={`flex items-center gap-[6px] ${statusToneClass(status)}`}
          >
            <Glyph name="dot" />
            <span>{statusLabel(status)}</span>
          </span>
        ) : null}
        {startError ? (
          <span className="text-alert" data-testid="scan-start-error">
            · {startError}
          </span>
        ) : null}

        <span className="ml-auto" />
        <Button
          type="button"
          onClick={handleClick}
          disabled={isBusy}
          data-testid="scan-trigger"
        >
          {isBusy ? "scanning…" : "run scan"}
        </Button>
      </div>

      {/* Bottom row: data sources + research-only disclaimer. Stacks below sm. */}
      <div
        className="flex flex-col sm:flex-row sm:items-center gap-[6px] sm:gap-[14px] px-[14px] py-[6px] border-t border-border text-dim"
        data-testid="footer-meta"
      >
        <span data-testid="footer-sources" className="flex items-center gap-[10px]">
          <span className="text-dim">sources</span>
          <a
            href="https://www.shodan.io"
            target="_blank"
            rel="noreferrer noopener"
            className="hover:text-text"
          >
            Shodan
          </a>
          <a
            href="https://nvd.nist.gov"
            target="_blank"
            rel="noreferrer noopener"
            className="hover:text-text"
          >
            NVD
          </a>
          <a
            href="https://www.maxmind.com"
            target="_blank"
            rel="noreferrer noopener"
            className="hover:text-text"
          >
            MaxMind GeoIP
          </a>
        </span>
        <span
          data-testid="footer-disclaimer"
          className="sm:ml-auto sm:text-right"
        >
          For security research and educational purposes only. Information is provided as-is; do not use for unauthorized access.
        </span>
      </div>
    </footer>
  );
}
