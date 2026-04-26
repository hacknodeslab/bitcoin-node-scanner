"use client";

import * as PopoverPrimitive from "@radix-ui/react-popover";
import { ComponentProps, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;

export const PopoverContent = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof PopoverPrimitive.Content>
>(function PopoverContent({ className, align = "start", sideOffset = 4, ...rest }, ref) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        ref={ref}
        align={align}
        sideOffset={sideOffset}
        className={cn(
          "z-50 bg-bg text-text border border-border outline-none",
          className,
        )}
        {...rest}
      />
    </PopoverPrimitive.Portal>
  );
});
