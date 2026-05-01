import { HTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

export interface TableRowProps extends HTMLAttributes<HTMLDivElement> {
  /** When true, renders the 2px primary left border for selected rows. */
  selected?: boolean;
}

/**
 * Dense table row. 9px vertical / 14px horizontal padding (/DESIGN.md).
 * Hover does NOT change background — operators are scanning, not browsing.
 * Selection state uses a 2px `primary` left border (the only spot in this
 * file where Bitcoin orange is allowed) plus an `accent-bg` row tint.
 */
export const TableRow = forwardRef<HTMLDivElement, TableRowProps>(function TableRow(
  { className, selected, ...rest },
  ref,
) {
  return (
    <div
      ref={ref}
      data-selected={selected ? "true" : undefined}
      className={cn(
        "py-[9px] px-[14px] border-b border-border-dim last:border-b-0",
        selected ? "border-l-2 border-l-primary pl-[12px] bg-accent-bg" : null,
        className,
      )}
      {...rest}
    />
  );
});

export interface TableExpandedRowProps extends HTMLAttributes<HTMLDivElement> {
  /** State colour for the 2px left border. */
  state: "alert" | "warn" | "ok" | "dim";
}

const STATE_BORDER: Record<TableExpandedRowProps["state"], string> = {
  alert: "border-l-alert",
  warn: "border-l-warn",
  ok: "border-l-ok",
  dim: "border-l-dim",
};

/**
 * Inline-expanded table row body. Switches background to `surface`, gains a
 * 2px left border in the row's state colour, and indents the findings body
 * to 32px so it anchors under the chevron column.
 */
export const TableExpandedRow = forwardRef<HTMLDivElement, TableExpandedRowProps>(
  function TableExpandedRow({ className, state, children, ...rest }, ref) {
    return (
      <div
        ref={ref}
        data-state={state}
        className={cn("bg-surface border-l-2", STATE_BORDER[state], className)}
        {...rest}
      >
        <div className="pl-[32px] pr-[14px] py-[14px] text-text-dim text-meta">
          {children}
        </div>
      </div>
    );
  },
);
