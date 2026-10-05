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
  const showScanStatus = vi.fn();
  const value: ExplorerCommands = {
    setQuery,
    startScan,
    setThemeMode,
    showScanStatus,
    ...overrides,
  };
  const utils = render(
    <ExplorerCommandsContext.Provider value={value}>
      <CommandPaletteRoot />
    </ExplorerCommandsContext.Provider>,
  );
  return { ...utils, setQuery, startScan, setThemeMode, showScanStatus };
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

  it("selecting a requiresArg command transitions to the argument-input row", () => {
    renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: filter country <code>"));
    // Arg row shows the command name + input; the command list is hidden.
    expect(screen.getByPlaceholderText("country code (e.g. US)…")).toBeTruthy();
    expect(screen.queryByText("scan: start")).toBeNull();
  });

  it("Enter in the argument-input row executes with the entered argument", () => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: filter country <code>"));
    const input = screen.getByPlaceholderText("country code (e.g. US)…");
    fireEvent.change(input, { target: { value: "DE" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(setQuery).toHaveBeenCalledWith("country=DE");
  });

  it("Esc in the argument-input row returns to the command list without executing", () => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: filter country <code>"));
    const input = screen.getByPlaceholderText("country code (e.g. US)…");
    fireEvent.change(input, { target: { value: "DE" } });
    fireEvent.keyDown(input, { key: "Escape" });
    // Back to the list view; the palette stays open and nothing ran.
    expect(screen.getByText("scan: start")).toBeTruthy();
    expect(setQuery).not.toHaveBeenCalled();
  });

  it("'scan: status <job_id>' routes the job id to showScanStatus", () => {
    const { showScanStatus } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("scan: status <job_id>"));
    const input = screen.getByPlaceholderText("job id…");
    fireEvent.change(input, { target: { value: "job-42" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(showScanStatus).toHaveBeenCalledWith("job-42");
  });

  it("Enter with an empty argument does not execute", () => {
    const { setQuery } = renderRoot();
    openPalette();
    fireEvent.click(screen.getByText("node: filter country <code>"));
    fireEvent.keyDown(document.activeElement!, { key: "Enter" });
    expect(setQuery).not.toHaveBeenCalled();
  });
});
