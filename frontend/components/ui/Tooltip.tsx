"use client";

import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { ComponentProps, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const TooltipProvider = TooltipPrimitive.Provider;
export const Tooltip = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;

export const TooltipContent = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof TooltipPrimitive.Content>
>(function TooltipContent({ className, sideOffset = 6, ...rest }, ref) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        ref={ref}
        sideOffset={sideOffset}
        className={cn(
          "z-50 bg-surface text-text-dim border border-border",
          "px-[8px] py-[4px] text-meta",
          className,
        )}
        {...rest}
      />
    </TooltipPrimitive.Portal>
  );
});
