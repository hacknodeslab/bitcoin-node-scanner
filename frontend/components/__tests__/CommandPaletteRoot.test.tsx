/**
 * CommandPaletteRoot wires `lib/commands.COMMAND_SPECS` to runtime actions
 * via the ExplorerCommandsContext. ⌘K opens the palette; clicking
 * "node: filter risk critical" should fire setQuery("risk=CRITICAL"), etc.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { CommandPaletteRoot } from "../explorer/CommandPaletteRoot";
import {
  ExplorerCommandsContext,
  type ExplorerCommands,
} from "../explorer/explorer-context";

function renderRoot(overrides?: Partial<ExplorerCommands>) {
  const setQuery = vi.fn();
  const startScan = vi.fn().mockResolvedValue(undefined);
  const setThemeMode = vi.fn();
  const value: ExplorerCommands = {
    setQuery,
    startScan,
    setThemeMode,
    ...overrides,
  };
  const utils = render(
    <ExplorerCommandsContext.Provider value={value}>
      <CommandPaletteRoot />
    </ExplorerCommandsContext.Provider>,
  );
  return { ...utils, setQuery, startScan, setThemeMode };
}

function openPalette() {
  fireEvent.keyDown(window, { key: "k", metaKey: true });
}

describe("CommandPaletteRoot", () => {
  it("⌘K opens the palette and renders the v0 command groups", () => {
    renderRoot();
    expect(screen.queryByText("scan: start")).toBeNull();
    openPalette();
    expect(screen.getByText("scan: start")).toBeTruthy();
    expect(screen.getByText("stats: refresh")).toBeTruthy();
    expect(screen.getByText("node: list")).toBeTruthy();
    expect(screen.getByText("node: filter risk critical")).toBeTruthy();
    expect(screen.getByText("vuln: list")).toBeTruthy();
    expect(screen.getByText("go: explorer")).toBeTruthy();
    expect(screen.getByText("palette: close")).toBeTruthy();
  });

  it("clicking 'node: filter risk critical' calls setQuery('risk=CRITICAL')", () => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: filter risk critical"));
    expect(setQuery).toHaveBeenCalledWith("risk=CRITICAL");
  });

  it("'node: filter blocklisted (any list)' sets blocklisted=true", () => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: filter blocklisted (any list)"));
    expect(setQuery).toHaveBeenCalledWith("blocklisted=true");
  });

  it.each(["firehol_level1", "spamhaus_drop", "feodo", "tor_exit"])(
    "'node: filter blocklist %s' sets blocklist=%s",
    (id) => {
      const { setQuery } = renderRoot();
      openPalette();
      fireEvent.click(screen.getByText(`node: filter blocklist ${id}`));
      expect(setQuery).toHaveBeenCalledWith(`blocklist=${id}`);
    },
  );

  it.each([
    ["node: filter abuse score ≥ 25 (abuseipdb)", "abuse_min=25"],
    ["node: filter abuse score ≥ 75 (abuseipdb)", "abuse_min=75"],
    ["node: filter reported (abuseipdb)", "reported=true"],
  ])("'%s' sets %s", (label, query) => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText(label));
    expect(setQuery).toHaveBeenCalledWith(query);
  });

  it("clicking 'node: clear filters' resets the query string", () => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: clear filters"));
    expect(setQuery).toHaveBeenCalledWith("");
  });

  it("clicking 'scan: start' calls startScan from context", () => {
    const { startScan } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("scan: start"));
    expect(startScan).toHaveBeenCalledTimes(1);
  });

  it("theme commands route through setThemeMode", () => {
    const { setThemeMode } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("theme: light"));
    expect(setThemeMode).toHaveBeenCalledWith("light");

    openPalette();
    fireEvent.click(screen.getByText("theme: dark"));
    expect(setThemeMode).toHaveBeenCalledWith("dark");

    openPalette();
    fireEvent.click(screen.getByText("theme: system"));
    expect(setThemeMode).toHaveBeenCalledWith("system");
  });

  it("Esc closes the palette without firing any action", () => {
    const { setQuery, startScan } = renderRoot();
    openPalette();
    expect(screen.getByText("scan: start")).toBeTruthy();
    fireEvent.keyDown(document.activeElement!, { key: "Escape" });
    // Palette closes; nothing was clicked.
    expect(setQuery).not.toHaveBeenCalled();
    expect(startScan).not.toHaveBeenCalled();
  });
});
