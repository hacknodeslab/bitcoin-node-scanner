"use client";

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

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      data-testid="theme-toggle"
      className={cn("flex items-center gap-[6px] text-meta", className)}
    >
      {THEME_MODES.map((option) => {
        const active = option === mode;
        return (
          <button
            key={option}
            type="button"
            role="radio"
            aria-checked={active}
            data-testid={`theme-option-${option}`}
            onClick={() => setMode(option)}
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
