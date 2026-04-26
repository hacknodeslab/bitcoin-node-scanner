"use client";

import { useState } from "react";
import { Glyph } from "@/components/ui/Glyph";
import { QueryBar } from "@/components/ui/QueryBar";

export interface QueryBarControllerProps {
  /** The currently-applied query (parent-owned). The input syncs to this. */
  value: string;
  /** Fired on Enter or when the input is cleared. */
  onApply: (raw: string) => void;
  /** Optional warning lines to surface from the grammar bridge. */
  warnings?: string[];
  /** Match count rendered on the active-filters row. */
  matchCount?: number;
}

/**
 * Controlled query bar. Owns a draft string locally and lifts it to the
 * parent on Enter (the only "apply" trigger). Renders the parsed-token
 * preview only for the *applied* value — not the live draft — so the user
 * can edit freely without thrashing the data fetch on every keystroke.
 */
export function QueryBarController({
  value,
  onApply,
  warnings,
  matchCount,
}: QueryBarControllerProps) {
  const [draft, setDraft] = useState(value);
  // Render-time sync (the pattern the React docs recommend over useEffect
  // → setState): when the parent-owned `value` changes externally — e.g.
  // a "clear" command — we reset the draft to match. Local typing never
  // updates `lastSynced`, so it never overwrites itself.
  const [lastSynced, setLastSynced] = useState(value);
  if (value !== lastSynced) {
    setLastSynced(value);
    setDraft(value);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onApply(draft);
  }

  return (
    <div data-testid="query-bar-controller">
      <form
        onSubmit={handleSubmit}
        className="flex items-center gap-[8px] px-[14px] py-[10px] border-b border-border bg-bg"
      >
        {/* Dim chevron in the input row (the orange chevron is reserved for
            the active-filters preview rendered by `QueryBar` below — it
            signals that a filter is currently applied, not just hovered). */}
        <Glyph name="chevron" className="text-dim" />
        <input
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="risk=critical exposed=true ↵ to apply"
          aria-label="filter query"
          data-testid="query-bar-input"
          className="bg-transparent text-text placeholder:text-dim text-body-sm flex-1 outline-none"
        />
        <span className="text-meta text-dim">↵ apply</span>
      </form>

      {value.trim() ? (
        <QueryBar query={value} matchCount={matchCount} />
      ) : null}

      {warnings && warnings.length > 0 ? (
        <div
          role="status"
          data-testid="query-bar-warnings"
          className="px-[14px] py-[6px] border-b border-border bg-bg text-meta text-warn"
        >
          {warnings.map((w, i) => (
            <div key={i}>· {w}</div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
