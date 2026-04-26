import { cn } from "@/lib/utils";

export type DeltaDirection = "rising-good" | "rising-bad" | "neutral";

export interface StatTileProps {
  label: string;
  value: string | number;
  delta?: { value: string; direction: DeltaDirection };
  className?: string;
}

/**
 * Stat tile for the explorer's 5-tile strip.
 *
 * Delta colour rule (/DESIGN.md): rising EXPOSED is bad → use `alert`. Rising
 * OK is good → use `ok`. The caller declares the direction; the tile colours
 * accordingly. There is no "auto-sign" detection: meaning is data-domain.
 */
export function StatTile({ label, value, delta, className }: StatTileProps) {
  const deltaClass =
    !delta
      ? ""
      : delta.direction === "rising-good"
        ? "text-ok"
        : delta.direction === "rising-bad"
          ? "text-alert"
          : "text-muted";

  return (
    <div className={cn("bg-bg px-[14px] py-[10px]", className)}>
      <div className="text-label uppercase text-dim tracking-[0.5px]">{label}</div>
      <div className="mt-[3px] text-mono-num">
        <span className="text-text">{value}</span>
        {delta ? (
          <span className={cn("ml-[4px] text-label", deltaClass)}>{delta.value}</span>
        ) : null}
      </div>
    </div>
  );
}
