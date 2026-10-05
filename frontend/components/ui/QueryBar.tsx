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
  (t) => t.key === "blocklisted" && t.value === "true",
  (t) => t.key === "blocklist",
  (t) => t.key === "reported" && t.value === "true",
  (t) => t.key === "abuse_min",
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
 * A bareword that is an IP address is shorthand for `ip=<addr>`, so pasting
 * an IP just works. Other barewords are not tokens: `splitQuery` reports them
 * so the grammar bridge can warn instead of silently ignoring them. The regex
 * anchors on `\w+=` so a stray `=` inside a bareword (`foo=bar=baz`) keeps
 * everything after the first `=` as the value.
 */
const TOKEN_RE = /(\w+)=(?:"([^"]*)"|(\S+))|(\S+)/g;

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^[0-9a-f]*:[0-9a-f:.]*$/i;

export function looksLikeIp(value: string): boolean {
  return IPV4_RE.test(value) || (IPV6_RE.test(value) && value.includes(":"));
}

export function splitQuery(input: string): { tokens: QueryToken[]; bareWords: string[] } {
  const tokens: QueryToken[] = [];
  const bareWords: string[] = [];
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  while ((m = TOKEN_RE.exec(input)) !== null) {
    if (m[4] !== undefined) {
      const word = m[4].replace(/^\[|\]$/g, "");
      if (looksLikeIp(word)) tokens.push({ key: "ip", value: word });
      else bareWords.push(m[4]);
      continue;
    }
    const value = m[2] !== undefined ? m[2] : m[3];
    tokens.push({ key: m[1], value });
  }
  return { tokens, bareWords };
}

export function parseQuery(input: string): QueryToken[] {
  return splitQuery(input).tokens;
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
