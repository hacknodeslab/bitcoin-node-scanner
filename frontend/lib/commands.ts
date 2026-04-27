/**
 * Palette ↔ REST registry.
 *
 * Every non-NAV palette command MUST resolve to a registered REST endpoint
 * (design.md D10). The parity test in `commands.test.ts` walks
 * `COMMAND_SPECS`, skips `NAV`, and asserts each `restEndpoint` exists in
 * `REST_ENDPOINTS`. NAV entries are frontend-only and exempt by design.
 *
 * v0 ships a subset of the D10 list: arg-needing commands
 * (`scan: status <job_id>`, `node: filter country <code>`, `node: open <ip>`)
 * and drawer-bound commands (`drawer: close`, `drawer: copy ip`) are
 * deferred — they're not invocable without UI we haven't shipped yet (§10
 * for the drawer, future palette modes for argument prompts). They are
 * tracked as parity debt alongside the existing CLI parity work.
 */

export type CommandGroupId = "SCAN" | "STATS" | "NODES" | "VULNERABILITIES" | "NAV";

export interface CommandSpec {
  /** Stable id used for testing and as React key. */
  id: string;
  group: CommandGroupId;
  /** Visible label. Lowercase, colon-separated, matches /DESIGN.md style. */
  label: string;
  /**
   * `METHOD /path`. Null for NAV commands (frontend-only). The path uses
   * `{param}` placeholders the same way the FastAPI router declares them.
   */
  restEndpoint: string | null;
  /** Optional right-aligned hint. */
  shortcut?: string;
}

/**
 * Authoritative list of REST endpoints exposed by the FastAPI app. Keep in
 * sync with `src/web/main.py` router includes. The parity test tolerates
 * additions here but fails fast if a command points at a path not in this
 * set.
 */
export const REST_ENDPOINTS: ReadonlySet<string> = new Set([
  "GET /api/v1/csrf-token",
  "GET /api/v1/stats",
  "GET /api/v1/nodes",
  "GET /api/v1/nodes/{id}/geo",
  "GET /api/v1/nodes/countries",
  "POST /api/v1/scans",
  "GET /api/v1/scans/{job_id}",
  "GET /api/v1/vulnerabilities",
  "GET /api/v1/l402/example",
]);

export const COMMAND_SPECS: readonly CommandSpec[] = [
  // SCAN
  { id: "scan.start", group: "SCAN", label: "scan: start", restEndpoint: "POST /api/v1/scans" },

  // STATS
  { id: "stats.refresh", group: "STATS", label: "stats: refresh", restEndpoint: "GET /api/v1/stats" },

  // NODES
  { id: "node.list", group: "NODES", label: "node: list", restEndpoint: "GET /api/v1/nodes" },
  { id: "node.clearFilters", group: "NODES", label: "node: clear filters", restEndpoint: "GET /api/v1/nodes" },
  {
    id: "node.filter.risk.critical",
    group: "NODES",
    label: "node: filter risk critical",
    restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.risk.high",
    group: "NODES",
    label: "node: filter risk high",
    restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.risk.medium",
    group: "NODES",
    label: "node: filter risk medium",
    restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.risk.low",
    group: "NODES",
    label: "node: filter risk low",
    restEndpoint: "GET /api/v1/nodes",
  },

  // VULNERABILITIES
  { id: "vuln.list", group: "VULNERABILITIES", label: "vuln: list", restEndpoint: "GET /api/v1/vulnerabilities" },

  // NAV (frontend-only — exempt from REST mapping)
  { id: "nav.explorer", group: "NAV", label: "go: explorer", restEndpoint: null },
  { id: "nav.paletteClose", group: "NAV", label: "palette: close", restEndpoint: null, shortcut: "esc" },
];
