"use client";

import { useCallback, useMemo, useState } from "react";
import { QueryBarController } from "./QueryBarController";
import { NodeTable } from "./NodeTable";
import { ExplorerFooter } from "./ExplorerFooter";
import { CommandPaletteRoot } from "./CommandPaletteRoot";
import {
  ExplorerCommandsContext,
  type ExplorerCommands,
} from "./explorer-context";
import { parseQueryToFilters } from "@/lib/query-grammar";
import { useScanJob } from "@/lib/hooks";

/**
 * Client-side root for the explorer. Owns:
 *   - The applied query string (lifted to NodeTable.filters via the grammar
 *     bridge and surfaced as warnings under the QueryBarController).
 *   - A single `useScanJob` instance, shared between the footer (status +
 *     manual button) and the command palette (`scan: start`). Without this
 *     lift, palette-triggered scans wouldn't surface status in the footer.
 *
 * Renders the footer + the CommandPaletteRoot inside this client tree so
 * both can reach the context. The page (server component) keeps the
 * surrounding flex column.
 */
export function Explorer() {
  const [appliedQuery, setAppliedQuery] = useState<string>("");

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

  return (
    <ExplorerCommandsContext.Provider value={commands}>
      <QueryBarController
        value={appliedQuery}
        onApply={setAppliedQuery}
        warnings={warnings}
      />
      <main className="flex-1">
        <NodeTable filters={filters} />
      </main>
      <ExplorerFooter job={scanJob.job ?? null} onStart={startScan} />
      <CommandPaletteRoot />
    </ExplorerCommandsContext.Provider>
  );
}
