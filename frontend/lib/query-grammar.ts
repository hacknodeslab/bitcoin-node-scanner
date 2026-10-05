/**
 * Bridge between the query-bar grammar (key=value tokens) and the
 * NodeListParams shape consumed by `useNodes`.
 *
 * The grammar is closed: only `risk`, `country`, `exposed`, `tor`, `example`,
 * `port`, `ip`, `blocklisted`, `blocklist`, `abuse_min`, `reported` are
 * accepted. A bare IP is shorthand for `ip=<addr>`; other bare words warn. Unknown keys produce diagnostics but are not silently
 * dropped — `tokensToFilters` returns a `warnings` array so the UI can
 * surface them inline if it wants.
 */
import { looksLikeIp, splitQuery, type QueryToken } from "@/components/ui/QueryBar";
import type { NodeListParams, RiskLevel } from "@/lib/api/types";
import { BLOCKLIST_IDS, isBlocklistId } from "@/lib/blocklists";

export type ExplorerFilters = Pick<
  NodeListParams,
  | "risk_level"
  | "country"
  | "exposed"
  | "tor"
  | "is_example"
  | "port"
  | "ip"
  | "blocklisted"
  | "blocklist"
  | "abuse_min"
  | "reported"
>;

export interface ParseResult {
  filters: ExplorerFilters;
  warnings: string[];
}

const VALID_RISK = new Set<RiskLevel>(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

function parseBool(value: string): boolean | "invalid" {
  const v = value.toLowerCase();
  if (v === "true" || v === "1" || v === "yes") return true;
  if (v === "false" || v === "0" || v === "no") return false;
  return "invalid";
}

export function tokensToFilters(tokens: QueryToken[]): ParseResult {
  const filters: ExplorerFilters = {};
  const warnings: string[] = [];

  for (const t of tokens) {
    switch (t.key.toLowerCase()) {
      case "risk": {
        const v = t.value.toUpperCase() as RiskLevel;
        if (!VALID_RISK.has(v)) {
          warnings.push(`risk=${t.value}: must be CRITICAL|HIGH|MEDIUM|LOW`);
          break;
        }
        filters.risk_level = v;
        break;
      }
      case "country":
        filters.country = t.value;
        break;
      case "exposed": {
        const b = parseBool(t.value);
        if (b === "invalid") {
          warnings.push(`exposed=${t.value}: must be true|false`);
          break;
        }
        filters.exposed = b;
        break;
      }
      case "tor": {
        const b = parseBool(t.value);
        if (b === "invalid") {
          warnings.push(`tor=${t.value}: must be true|false`);
          break;
        }
        if (b === false) {
          warnings.push("tor=false is not supported in v0; omit the filter or use tor=true");
          break;
        }
        filters.tor = true;
        break;
      }
      case "example": {
        const b = parseBool(t.value);
        if (b === "invalid") {
          warnings.push(`example=${t.value}: must be true|false`);
          break;
        }
        filters.is_example = b;
        break;
      }
      case "port": {
        const n = Number(t.value);
        if (!Number.isInteger(n) || n < 1 || n > 65535) {
          warnings.push(`port=${t.value}: must be an integer between 1 and 65535`);
          break;
        }
        filters.port = n;
        break;
      }
      case "ip": {
        const ip = t.value.replace(/^\[|\]$/g, "");
        if (!looksLikeIp(ip)) {
          warnings.push(`ip=${t.value}: must be an IPv4 or IPv6 address (exact match)`);
          break;
        }
        filters.ip = ip;
        break;
      }
      case "abuse_min": {
        const n = Number(t.value);
        if (!Number.isInteger(n) || n < 0 || n > 100) {
          warnings.push(`abuse_min=${t.value}: must be an integer between 0 and 100`);
          break;
        }
        filters.abuse_min = n;
        break;
      }
      case "reported": {
        const b = parseBool(t.value);
        if (b === "invalid") {
          warnings.push(`reported=${t.value}: must be true`);
          break;
        }
        if (b === false) {
          warnings.push("reported=false is not supported; omit the filter or use reported=true");
          break;
        }
        filters.reported = true;
        break;
      }
      case "blocklisted": {
        const b = parseBool(t.value);
        if (b === "invalid") {
          warnings.push(`blocklisted=${t.value}: must be true`);
          break;
        }
        if (b === false) {
          warnings.push("blocklisted=false is not supported; omit the filter or use blocklisted=true");
          break;
        }
        filters.blocklisted = true;
        break;
      }
      case "blocklist": {
        const id = t.value.toLowerCase();
        if (!isBlocklistId(id)) {
          warnings.push(`blocklist=${t.value}: must be ${BLOCKLIST_IDS.join("|")}`);
          break;
        }
        filters.blocklist = id;
        break;
      }
      default:
        warnings.push(`unknown key: ${t.key}`);
    }
  }

  return { filters, warnings };
}

export function parseQueryToFilters(input: string): ParseResult {
  const { tokens, bareWords } = splitQuery(input);
  const result = tokensToFilters(tokens);
  for (const word of bareWords) {
    result.warnings.push(`"${word}" ignored: use key=value (e.g. ip=1.2.3.4 or risk=high)`);
  }
  return result;
}
