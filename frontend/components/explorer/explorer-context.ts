"use client";

import { createContext, useContext } from "react";
import type { ThemeMode } from "@/lib/theme";

/**
 * Actions surfaced from `Explorer` to the `CommandPaletteRoot`. Stats and
 * node refreshes are handled with SWR `mutate` directly — they don't need
 * to pass through the context. Anything that touches per-page state
 * (applied query, scan-job lifecycle the footer owns, theme mode) must
 * come through here so the palette can reach it.
 */
export interface ExplorerCommands {
  setQuery: (q: string) => void;
  startScan: () => Promise<void>;
  setThemeMode: (mode: ThemeMode) => void;
}

export const ExplorerCommandsContext = createContext<ExplorerCommands | null>(null);

export function useExplorerCommands(): ExplorerCommands {
  const ctx = useContext(ExplorerCommandsContext);
  if (!ctx) {
    throw new Error("useExplorerCommands must be used within <Explorer>");
  }
  return ctx;
}
