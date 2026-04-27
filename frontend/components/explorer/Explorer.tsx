"use client";

import { useCallback, useMemo, useState } from "react";
import { QueryBarController } from "./QueryBarController";
import { NodeTable } from "./NodeTable";
import { ExplorerFooter } from "./ExplorerFooter";
import { CommandPaletteRoot } from "./CommandPaletteRoot";
import { NodeDetailDrawer } from "./NodeDetailDrawer";
import {
  ExplorerCommandsContext,
  type ExplorerCommands,
} from "./explorer-context";
import { parseQueryToFilters } from "@/lib/query-grammar";
import { useNodes, useScanJob } from "@/lib/hooks";

/**
 * Client-side root for the explorer. Owns:
 *   - The applied query string (lifted to NodeTable.filters via the
 *     grammar bridge and surfaced as warnings under the QueryBarController).
 *   - The selected IP — opens NodeDetailDrawer when non-null.
 *   - A small "recent nodes" useNodes call that feeds the drawer's sliver.
 *     SWR dedupes by URL key, so this overlaps with NodeTable's fetch only
 *     when the params match — for the recent-20 sliver we keep parameters
 *     fixed (sort by last_seen desc, limit 20) regardless of the table's
 *     current sort, so the sliver always reads "RECENT".
 *   - A single useScanJob instance, shared between the footer (status +
 *     manual button) and the command palette ("scan: start").
 */
export function Explorer() {
  const [appliedQuery, setAppliedQuery] = useState<string>("");
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  const { filters, warnings } = useMemo(
    () => parseQueryToFilters(appliedQuery),
    [appliedQuery],
  );

  const scanJob = useScanJob();

  const startScan = useCallback(async () => {
    await scanJob.start();
  }, [scanJob]);

  const commands: ExplorerCommands = useMemo(
    () => ({ setQuery: setAppliedQuery, startScan }),
    [startScan],
  );

  // Stable sliver feed — top 20 by last_seen, independent of the table's
  // sort/filter so opening the drawer always shows recent activity.
  const recent = useNodes({ sort_by: "last_seen", sort_dir: "desc", limit: 20 });

  return (
    <ExplorerCommandsContext.Provider value={commands}>
      <QueryBarController
        value={appliedQuery}
        onApply={setAppliedQuery}
        warnings={warnings}
      />
      <main className="flex-1">
        <NodeTable
          filters={filters}
          selectedIp={selectedIp}
          onSelectNode={setSelectedIp}
        />
      </main>
      <ExplorerFooter job={scanJob.job ?? null} onStart={startScan} />
      <NodeDetailDrawer
        ip={selectedIp}
        onOpenChange={(o) => {
          if (!o) setSelectedIp(null);
        }}
        sliverNodes={recent.nodes ?? []}
        onActivateIp={setSelectedIp}
      />
      <CommandPaletteRoot />
    </ExplorerCommandsContext.Provider>
  );
}
