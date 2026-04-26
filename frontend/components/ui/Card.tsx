import { HTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  function Card({ className, ...rest }, ref) {
    return (
      <div
        ref={ref}
        className={cn("bg-surface border border-border-dim", className)}
        {...rest}
      />
    );
  },
);

export const CardLabel = forwardRef<
  HTMLDivElement,
  HTMLAttributes<HTMLDivElement>
>(function CardLabel({ className, ...rest }, ref) {
  return (
    <div
      ref={ref}
      className={cn("text-label uppercase text-dim px-[12px] py-[8px]", className)}
      {...rest}
    />
  );
});

export const CardRow = forwardRef<
  HTMLDivElement,
  HTMLAttributes<HTMLDivElement>
>(function CardRow({ className, ...rest }, ref) {
  return (
    <div
      ref={ref}
      className={cn(
        "px-[12px] py-[8px] border-b border-border-dim last:border-b-0",
        className,
      )}
      {...rest}
    />
  );
});
