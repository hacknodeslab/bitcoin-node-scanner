"use client";

import * as ScrollAreaPrimitive from "@radix-ui/react-scroll-area";
import { ComponentProps, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const ScrollArea = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof ScrollAreaPrimitive.Root>
>(function ScrollArea({ className, children, ...rest }, ref) {
  return (
    <ScrollAreaPrimitive.Root
      ref={ref}
      className={cn("relative overflow-hidden", className)}
      {...rest}
    >
      <ScrollAreaPrimitive.Viewport className="h-full w-full">
        {children}
      </ScrollAreaPrimitive.Viewport>
      <ScrollAreaPrimitive.Scrollbar
        orientation="vertical"
        className="flex select-none touch-none p-[1px] bg-bg w-[8px]"
      >
        <ScrollAreaPrimitive.Thumb className="flex-1 bg-border" />
      </ScrollAreaPrimitive.Scrollbar>
      <ScrollAreaPrimitive.Corner />
    </ScrollAreaPrimitive.Root>
  );
});
