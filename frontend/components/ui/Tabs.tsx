"use client";

import * as TabsPrimitive from "@radix-ui/react-tabs";
import { ComponentProps, forwardRef } from "react";
import { cn } from "@/lib/utils";

/**
 * Tabs — Radix anatomy with /DESIGN.md token overrides.
 * Active tab uses 1px `primary` bottom border (legitimate use site).
 */
export const Tabs = TabsPrimitive.Root;

export const TabsList = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof TabsPrimitive.List>
>(function TabsList({ className, ...rest }, ref) {
  return (
    <TabsPrimitive.List
      ref={ref}
      className={cn(
        "flex border-b border-border text-meta px-[16px] overflow-x-auto",
        className,
      )}
      {...rest}
    />
  );
});

export const TabsTrigger = forwardRef<
  HTMLButtonElement,
  ComponentProps<typeof TabsPrimitive.Trigger>
>(function TabsTrigger({ className, ...rest }, ref) {
  return (
    <TabsPrimitive.Trigger
      ref={ref}
      className={cn(
        "py-[10px] mr-[18px] -mb-px whitespace-nowrap text-muted",
        // Radix sets data-state="active" on the active trigger; tie the
        // primary bottom border to that — the only place outside Button
        // (l402) where Bitcoin orange appears in this file.
        "data-[state=active]:text-text data-[state=active]:border-b data-[state=active]:border-primary",
        "outline-none focus-visible:text-text",
        className,
      )}
      {...rest}
    />
  );
});

export const TabsContent = forwardRef<
  HTMLDivElement,
  ComponentProps<typeof TabsPrimitive.Content>
>(function TabsContent({ className, ...rest }, ref) {
  return <TabsPrimitive.Content ref={ref} className={cn(className)} {...rest} />;
});
