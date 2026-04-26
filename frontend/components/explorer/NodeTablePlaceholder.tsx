import { TableRow } from "@/components/ui/TableRow";

/**
 * Visual placeholder for the explorer's node table. The real table (§8.4)
 * will replace this with sortable headers, virtualized rows, and inline
 * expansion. For now we render the column header strip and an empty-state
 * row so the layout is honest about what's missing.
 */
const COLUMNS = [
  { key: "ip", label: "IP", width: "w-[180px]" },
  { key: "port", label: "PORT", width: "w-[60px]" },
  { key: "version", label: "VERSION", width: "w-[160px]" },
  { key: "country", label: "CC", width: "w-[40px]" },
  { key: "risk", label: "RISK", width: "w-[80px]" },
  { key: "flags", label: "FLAGS", width: "" },
];

export function NodeTablePlaceholder() {
  return (
    <div data-testid="node-table-placeholder">
      <div className="grid grid-cols-[180px_60px_160px_40px_80px_1fr] gap-[14px] px-[14px] py-[9px] border-b border-border text-label uppercase text-dim tracking-[0.5px]">
        {COLUMNS.map((c) => (
          <div key={c.key}>{c.label}</div>
        ))}
      </div>
      <TableRow>
        <span className="text-body-sm text-muted">
          · table wires up in §8.4 — query bar + filters arrive in §8.2
        </span>
      </TableRow>
    </div>
  );
}
