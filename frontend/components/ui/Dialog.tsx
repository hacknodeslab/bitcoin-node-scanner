"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { ComponentProps, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogPortal = DialogPrimitive.Portal;
export const DialogClose = DialogPrimitive.Close;
export const DialogTitle = DialogPrimitive.Title;
export const DialogDescription = DialogPrimitive.Description;

/**
 * Dialog overlay. /DESIGN.md allows ONLY a flat alpha dim under the command
 * palette — no `backdrop-blur`, no glassmorphism. The rgba is the documented
 * exception (`rgba(0,0,0,0.5)`); using Tailwind's arbitrary-value syntax
 * keeps it lint-clean and out of inline `style`.
 */
export const DialogOverlay = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof DialogPrimitive.Overlay>
>(function DialogOverlay({ className, ...rest }, ref) {
  return (
    <DialogPrimitive.Overlay
      ref={ref}
      className={cn("fixed inset-0 z-40 bg-[rgba(0,0,0,0.5)]", className)}
      {...rest}
    />
  );
});

export const DialogContent = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof DialogPrimitive.Content>
>(function DialogContent({ className, children, ...rest }, ref) {
  return (
    <DialogPortal>
      <DialogOverlay />
      <DialogPrimitive.Content
        ref={ref}
        className={cn(
          "fixed z-50 bg-bg border border-border outline-none",
          "left-1/2 top-[80px] -translate-x-1/2 w-full max-w-[560px]",
          className,
        )}
        {...rest}
      >
        {children}
      </DialogPrimitive.Content>
    </DialogPortal>
  );
});
