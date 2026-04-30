"use client";

import { useMemo, useState } from "react";
import { mutate } from "swr";
import {
  CommandPalette,
  type CommandGroup,
  type CommandItem,
} from "@/components/ui/CommandPalette";
import { COMMAND_SPECS, type CommandSpec } from "@/lib/commands";
import { useExplorerCommands } from "./explorer-context";

const GROUP_ORDER = ["SCAN", "STATS", "NODES", "VULNERABILITIES", "NAV"] as const;

/**
 * Mounts the global ⌘K listener and wires each shipped command spec to a
 * runtime action. Lives inside `Explorer` so it can read the
 * ExplorerCommandsContext for state setters; SWR keys are mutated directly
 * (no context plumbing needed for the read-only surface).
 *
 * Specs that point at endpoints needing argument prompts (`scan: status`,
 * `node: filter country <code>`, `node: open <ip>`) and drawer-bound
 * commands (`drawer: ...`) are intentionally absent from COMMAND_SPECS —
 * see lib/commands.ts for the rationale and the parity-debt list.
 */
export function CommandPaletteRoot() {
  const [open, setOpen] = useState(false);
  const cmds = useExplorerCommands();

  const groups: CommandGroup[] = useMemo(() => {
    function actionFor(spec: CommandSpec): () => void | Promise<void> {
      switch (spec.id) {
        case "scan.start":
          return () => cmds.startScan();
        case "stats.refresh":
          return () => {
            mutate("/api/v1/stats");
          };
        case "node.list":
        case "node.clearFilters":
          return () => {
            cmds.setQuery("");
            mutate((key) => typeof key === "string" && key.startsWith("/api/v1/nodes"));
          };
        case "node.filter.risk.critical":
          return () => cmds.setQuery("risk=CRITICAL");
        case "node.filter.risk.high":
          return () => cmds.setQuery("risk=HIGH");
        case "node.filter.risk.medium":
          return () => cmds.setQuery("risk=MEDIUM");
        case "node.filter.risk.low":
          return () => cmds.setQuery("risk=LOW");
        case "vuln.list":
          return () => {
            mutate("/api/v1/vulnerabilities");
          };
        case "nav.explorer":
          // SPA root is the explorer in v0; future nav targets land here.
          return () => {};
        case "nav.paletteClose":
          return () => setOpen(false);
        case "theme.dark":
          return () => cmds.setThemeMode("dark");
        case "theme.light":
          return () => cmds.setThemeMode("light");
        case "theme.system":
          return () => cmds.setThemeMode("system");
        default:
          return () => {};
      }
    }

    const byGroup = new Map<string, CommandItem[]>();
    for (const spec of COMMAND_SPECS) {
      const item: CommandItem = {
        id: spec.id,
        label: spec.label,
        shortcut: spec.shortcut,
        onRun: actionFor(spec),
      };
      const list = byGroup.get(spec.group) ?? [];
      list.push(item);
      byGroup.set(spec.group, list);
    }

    return GROUP_ORDER.filter((g) => byGroup.has(g)).map((g) => ({
      label: g,
      items: byGroup.get(g)!,
    }));
  }, [cmds]);

  return (
    <CommandPalette
      open={open}
      onOpenChange={setOpen}
      groups={groups}
      installShortcut
    />
  );
}
