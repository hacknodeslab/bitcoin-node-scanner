/**
 * Palette ↔ REST registry.
 *
 * Every non-NAV palette command MUST resolve to a registered REST endpoint
 * (design.md D10). The parity test in `commands.test.ts` walks
 * `COMMAND_SPECS`, skips `NAV`, and asserts each `restEndpoint` exists in
 * `REST_ENDPOINTS`. NAV entries are frontend-only and exempt by design.
 *
 * v0 ships the full D10 command set except the drawer-bound commands
 * (`drawer: close`, `drawer: copy ip`) — deferred until §10 ships, tracked
 * as parity debt alongside the existing CLI parity work. Argument-taking
 * commands (`scan: status <job_id>`, `node: filter country <code>`) are
 * shipped via the palette's argument-input mode (spec `requiresArg`).
 * (`node: open <ip>` was dropped: the QueryBar already covers IP lookup
 * via `GET /api/v1/nodes?ip=`.)
 */

import { BLOCKLIST_IDS } from "@/lib/blocklists";

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
  /**
   * When true, running the command opens the palette's argument-input row
   * instead of executing immediately; Enter there executes with the arg.
   */
  requiresArg?: boolean;
  /** Placeholder shown in the argument-input row. */
  argPlaceholder?: string;
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
  "GET /api/v1/trends",
  "GET /api/v1/credits",
  "GET /api/v1/export",
  "POST /api/v1/import",
  "POST /api/v1/enrich-geo",
]);

export const COMMAND_SPECS: readonly CommandSpec[] = [
  // SCAN
  { id: "scan.start", group: "SCAN", label: "scan: start", restEndpoint: "POST /api/v1/scans" },
  {
    id: "scan.status",
    group: "SCAN",
    label: "scan: status <job_id>",
    restEndpoint: "GET /api/v1/scans/{job_id}",
    requiresArg: true,
    argPlaceholder: "job id…",
  },

  // STATS
  { id: "stats.refresh", group: "STATS", label: "stats: refresh", restEndpoint: "GET /api/v1/stats" },

  // NODES
  { id: "node.list", group: "NODES", label: "node: list", restEndpoint: "GET /api/v1/nodes" },
  { id: "node.clearFilters", group: "NODES", label: "node: clear filters", restEndpoint: "GET /api/v1/nodes" },
  {
    id: "node.filter.country",
    group: "NODES",
    label: "node: filter country <code>",
    restEndpoint: "GET /api/v1/nodes",
    requiresArg: true,
    argPlaceholder: "country code (e.g. US)…",
  },
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
  {
      id: "node.filter.port.8333",
      group: "NODES",
      label: "node: filter port 8333 (p2p)",
      restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.blocklisted",
    group: "NODES",
    label: "node: filter blocklisted (any list)",
    restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.abuse.25",
    group: "NODES",
    label: "node: filter abuse score ≥ 25 (abuseipdb)",
    restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.abuse.75",
    group: "NODES",
    label: "node: filter abuse score ≥ 75 (abuseipdb)",
    restEndpoint: "GET /api/v1/nodes",
  },
  {
    id: "node.filter.reported",
    group: "NODES",
    label: "node: filter reported (abuseipdb)",
    restEndpoint: "GET /api/v1/nodes",
  },
  // One command per list id: `node.filter.blocklist.<id>` → `blocklist=<id>`.
  ...BLOCKLIST_IDS.map(
    (id): CommandSpec => ({
      id: `node.filter.blocklist.${id}`,
      group: "NODES",
      label: `node: filter blocklist ${id}`,
      restEndpoint: "GET /api/v1/nodes",
    }),
  ),

  // VULNERABILITIES
  { id: "vuln.list", group: "VULNERABILITIES", label: "vuln: list", restEndpoint: "GET /api/v1/vulnerabilities" },

  // NAV (frontend-only — exempt from REST mapping)
  { id: "nav.explorer", group: "NAV", label: "go: explorer", restEndpoint: null },
  { id: "nav.paletteClose", group: "NAV", label: "palette: close", restEndpoint: null, shortcut: "esc" },
  { id: "theme.dark", group: "NAV", label: "theme: dark", restEndpoint: null },
  { id: "theme.light", group: "NAV", label: "theme: light", restEndpoint: null },
  { id: "theme.system", group: "NAV", label: "theme: system", restEndpoint: null },
];
