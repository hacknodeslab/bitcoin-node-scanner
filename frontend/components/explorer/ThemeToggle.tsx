"use client";

import { useRef, type KeyboardEvent } from "react";

import { useTheme } from "@/components/providers/ThemeProvider";
import { THEME_MODES, type ThemeMode } from "@/lib/theme";
import { cn } from "@/lib/utils";

const LABELS: Record<ThemeMode, string> = {
  dark: "dark",
  light: "light",
  system: "system",
};

/**
 * Three-state segmented control for theme selection. Lives in the TopNav.
 * Active option carries the same `border-b border-primary` treatment as the
 * Tabs primitive's active trigger, keeping the visual vocabulary consistent
 * across the explorer's chrome.
 */
export function ThemeToggle({ className }: { className?: string }) {
  const { mode, setMode } = useTheme();
  const buttonRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (index + 1) % THEME_MODES.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (index - 1 + THEME_MODES.length) % THEME_MODES.length;
    }
    if (nextIndex === null) return;
    event.preventDefault();
    const nextOption = THEME_MODES[nextIndex];
    setMode(nextOption);
    buttonRefs.current[nextIndex]?.focus();
  };

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      data-testid="theme-toggle"
      className={cn("flex items-center gap-[6px] text-meta", className)}
    >
      {THEME_MODES.map((option, index) => {
        const active = option === mode;
        return (
          <button
            key={option}
            ref={(el) => {
              buttonRefs.current[index] = el;
            }}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            data-testid={`theme-option-${option}`}
            onClick={() => setMode(option)}
            onKeyDown={(event) => handleKeyDown(event, index)}
            className={cn(
              "px-[4px] pb-[2px] border-b",
              active
                ? "text-text border-primary"
                : "text-muted border-transparent hover:text-text",
            )}
          >
            {LABELS[option]}
          </button>
        );
      })}
    </div>
  );
}
