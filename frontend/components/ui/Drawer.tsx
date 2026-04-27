"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { DialogOverlay, DialogPortal } from "./Dialog";
import { Glyph } from "./Glyph";

export interface DrawerSliverItem {
  id: string;
  label: string;
  active?: boolean;
  onActivate?: () => void;
}

export interface DrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Recent nodes shown in the 180px sliver. */
  sliverItems?: DrawerSliverItem[];
  sliverLabel?: string;
  /** Drawer content (header / tabs / body / footer). */
  children: ReactNode;
  className?: string;
}

/**
 * Node detail drawer. /DESIGN.md anatomy:
 *   - 180px sliver of recent nodes at opacity 0.45
 *   - active sliver row at full opacity, `surface` bg, 2px `primary` left border
 *   - main panel flexes to fill remaining width
 *
 * Focus trap, Esc-to-close and tab cycling come from Radix Dialog.
 */
export function Drawer({
  open,
  onOpenChange,
  sliverItems,
  sliverLabel = "RECENT",
  children,
  className,
}: DrawerProps) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPortal>
        <DialogOverlay />
        <DialogPrimitive.Content
          className={cn(
            "fixed z-50 inset-y-0 right-0 w-full max-w-[1200px]",
            "bg-bg border-l border-border outline-none flex",
            className,
          )}
        >
          {sliverItems && sliverItems.length > 0 ? (
            <aside className="w-[180px] border-r border-border flex-shrink-0 opacity-100">
              <div className="px-[12px] py-[8px] text-label uppercase text-dim border-b border-border tracking-[0.6px]">
                {sliverLabel}
              </div>
              <ul>
                {sliverItems.map((item) => (
                  <li
                    key={item.id}
                    onClick={item.onActivate}
                    className={cn(
                      "px-[12px] py-[8px] border-b border-border-dim cursor-pointer text-body-sm",
                      item.active
                        ? // Active row: full opacity, surface bg, 2px primary left border.
                          "opacity-100 bg-surface border-l-2 border-l-primary text-text"
                        : "opacity-[0.45] text-muted",
                    )}
                  >
                    {item.label}
                  </li>
                ))}
              </ul>
            </aside>
          ) : null}
          <div className="flex-1 min-w-0 flex flex-col">{children}</div>
        </DialogPrimitive.Content>
      </DialogPortal>
    </DialogPrimitive.Root>
  );
}

export function DrawerCloseButton({ className }: { className?: string }) {
  return (
    <DialogPrimitive.Close
      className={cn(
        "ml-auto text-dim text-meta cursor-pointer hover:text-text outline-none",
        className,
      )}
      aria-label="Close drawer"
    >
      <Glyph name="cross" />
    </DialogPrimitive.Close>
  );
}

// Re-export DialogTitle / DialogDescription for accessibility — Radix Dialog
// requires both for screen readers.
export { DialogTitle as DrawerTitle, DialogDescription as DrawerDescription } from "./Dialog";
