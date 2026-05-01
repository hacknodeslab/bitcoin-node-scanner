/**
 * Bridge between the query-bar grammar (key=value tokens) and the
 * NodeListParams shape consumed by `useNodes`.
 *
 * The grammar is closed: only `risk`, `country`, `exposed`, `tor`, `example`
 * are accepted. Unknown keys produce diagnostics but are not silently
 * dropped — `tokensToFilters` returns a `warnings` array so the UI can
 * surface them inline if it wants.
 */
import { parseQuery, type QueryToken } from "@/components/ui/QueryBar";
import type { NodeListParams, RiskLevel } from "@/lib/api/types";

export type ExplorerFilters = Pick<
  NodeListParams,
  "risk_level" | "country" | "exposed" | "tor" | "is_example"
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
      default:
        warnings.push(`unknown key: ${t.key}`);
    }
  }

  return { filters, warnings };
}

export function parseQueryToFilters(input: string): ParseResult {
  return tokensToFilters(parseQuery(input));
}
