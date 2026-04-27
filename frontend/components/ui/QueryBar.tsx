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
 * Tokenises a query string into ordered key=value pairs.
 *
 * Grammar:
 *   - `key=value` — bareword value, terminated by whitespace.
 *   - `key="quoted value"` — value may contain spaces; surrounding double
 *     quotes are stripped from the captured value.
 *
 * Bareword segments without `=` are dropped — the grammar requires explicit
 * fields. The regex anchors on `\w+=` so a stray `=` inside a bareword
 * (`foo=bar=baz`) keeps everything after the first `=` as the value.
 */
const TOKEN_RE = /(\w+)=(?:"([^"]*)"|(\S+))/g;

export function parseQuery(input: string): QueryToken[] {
  const tokens: QueryToken[] = [];
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  while ((m = TOKEN_RE.exec(input)) !== null) {
    const value = m[2] !== undefined ? m[2] : m[3];
    tokens.push({ key: m[1], value });
  }
  return tokens;
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
