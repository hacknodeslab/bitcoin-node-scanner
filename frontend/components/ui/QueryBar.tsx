import { cn } from "@/lib/utils";
import { Glyph } from "./Glyph";

/**
 * Query-bar grammar: `key=value` tokens whose values map to colour roles.
 * Per /DESIGN.md:
 *   - keys → muted
 *   - `=`  → dim
 *   - values default → text
 *   - "ok-coded" values (e.g. tor=false, exposed=false) → ok green
 *   - "alert-coded" values (e.g. exposed=true, stale=true) → alert red
 */
export interface QueryToken {
  key: string;
  value: string;
}

const ALERT_RULES: Array<(t: QueryToken) => boolean> = [
  (t) => t.key === "exposed" && t.value === "true",
  (t) => t.key === "stale" && t.value === "true",
  (t) => t.key === "risk" && /^(critical|high)$/i.test(t.value),
];

const OK_RULES: Array<(t: QueryToken) => boolean> = [
  (t) => t.key === "exposed" && t.value === "false",
  (t) => t.key === "stale" && t.value === "false",
  (t) => t.key === "tor" && t.value === "false",
];

function valueToneClass(t: QueryToken): string {
  if (ALERT_RULES.some((r) => r(t))) return "text-alert";
  if (OK_RULES.some((r) => r(t))) return "text-ok";
  return "text-text";
}

/**
 * Tokenises a query string into ordered key=value pairs. Whitespace-separated.
 * Tokens without `=` are dropped — the grammar requires explicit fields.
 */
export function parseQuery(input: string): QueryToken[] {
  return input
    .split(/\s+/)
    .filter(Boolean)
    .map((seg) => {
      const eq = seg.indexOf("=");
      if (eq === -1) return null;
      return { key: seg.slice(0, eq), value: seg.slice(eq + 1) };
    })
    .filter((t): t is QueryToken => t !== null);
}

export interface QueryBarProps {
  query: string;
  matchCount?: number;
  className?: string;
}

export function QueryBar({ query, matchCount, className }: QueryBarProps) {
  const tokens = parseQuery(query);
  return (
    <div
      className={cn(
        "flex items-center gap-[8px] px-[14px] py-[10px] border-b border-border bg-bg flex-wrap",
        className,
      )}
    >
      {/* The `›` prompt is one of the legitimate primary uses (/DESIGN.md). */}
      <Glyph name="chevron" className="text-primary" />
      {tokens.length === 0 ? (
        <span className="text-dim text-body-sm">type a key=value query…</span>
      ) : (
        tokens.map((t, i) => (
          <span key={i} className="text-body-sm">
            <span className="text-muted">{t.key}</span>
            <span className="text-dim">=</span>
            <span className={valueToneClass(t)}>{t.value}</span>
          </span>
        ))
      )}
      {matchCount !== undefined ? (
        <span className="ml-auto text-meta text-dim">{matchCount} match</span>
      ) : null}
    </div>
  );
}
