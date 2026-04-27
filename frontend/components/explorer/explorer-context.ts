"use client";

import { createContext, useContext } from "react";

/**
 * Actions surfaced from `Explorer` to the `CommandPaletteRoot`. Stats and
 * node refreshes are handled with SWR `mutate` directly — they don't need
 * to pass through the context. Anything that touches per-page state
 * (applied query, scan-job lifecycle the footer owns) must come through
 * here so the palette can reach it.
 */
export interface ExplorerCommands {
  setQuery: (q: string) => void;
  startScan: () => Promise<void>;
}

export const ExplorerCommandsContext = createContext<ExplorerCommands | null>(null);

export function useExplorerCommands(): ExplorerCommands {
  const ctx = useContext(ExplorerCommandsContext);
  if (!ctx) {
    throw new Error("useExplorerCommands must be used within <Explorer>");
  }
  return ctx;
}
