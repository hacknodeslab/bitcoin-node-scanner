"use client";

import { useEffect, useState, useRef, ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { cn } from "@/lib/utils";
import { DialogOverlay, DialogPortal, DialogTitle, DialogDescription } from "./Dialog";
import { Glyph } from "./Glyph";

export interface CommandItem {
  id: string;
  label: string;
  /** Optional shortcut hint shown right-aligned (e.g. "↵", "G N"). */
  shortcut?: string;
  onRun: () => void;
}

export interface CommandGroup {
  /** Uppercase label header (e.g. "SCAN", "NODES"). */
  label: string;
  items: CommandItem[];
}

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  groups: CommandGroup[];
  placeholder?: string;
  /**
   * Optional global ⌘K listener flag. When true, the component installs a
   * window-level keydown listener that toggles `open`. Disable when an
   * outer component already handles the shortcut (avoids double toggle).
   */
  installShortcut?: boolean;
}

function isTypingInInput(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || target.isContentEditable;
}

/**
 * Command palette — ⌘K overlay following /DESIGN.md anatomy:
 *   - flat alpha backdrop (no blur)
 *   - panel max-width 560px, bg, 1px border
 *   - input row: `›` prompt (primary), typed query, blinking caret, count meta
 *   - grouped items with label headers, single-line entries
 *   - focused item: surface bg + 2px primary left border (no horizontal shift)
 *   - footer: kbd hints (`↑↓ navigate`, `↵ run`, `esc close`)
 */
export function CommandPalette({
  open,
  onOpenChange,
  groups,
  placeholder = "search commands…",
  installShortcut = true,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [focusedIndex, setFocusedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Filter items by case-insensitive substring match on label.
  const filtered = groups
    .map((g) => ({
      ...g,
      items: g.items.filter((i) =>
        i.label.toLowerCase().includes(query.toLowerCase().trim()),
      ),
    }))
    .filter((g) => g.items.length > 0);

  const flatItems = filtered.flatMap((g) => g.items);
  const matchCount = flatItems.length;

  // Auto-focus the input when opening, and reset state.
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  // Optional global ⌘K / Ctrl+K listener.
  useEffect(() => {
    if (!installShortcut) return;
    const onKey = (e: KeyboardEvent) => {
      const isToggle =
        (e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K");
      if (!isToggle) return;
      // Don't hijack while user is typing in another input.
      if (!open && isTypingInInput(e.target)) return;
      e.preventDefault();
      onOpenChange(!open);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange, installShortcut]);

  const runFocused = () => {
    const item = flatItems[focusedIndex];
    if (!item) return;
    item.onRun();
    onOpenChange(false);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIndex((i) => (i + 1) % Math.max(matchCount, 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIndex((i) => (i - 1 + matchCount) % Math.max(matchCount, 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      runFocused();
    }
  };

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPortal>
        <DialogOverlay />
        <DialogPrimitive.Content
          className={cn(
            "fixed z-50 left-1/2 top-[80px] -translate-x-1/2",
            "w-full max-w-[560px] bg-bg border border-border outline-none",
          )}
          onKeyDown={onKeyDown}
        >
          <DialogTitle className="sr-only">Command palette</DialogTitle>
          <DialogDescription className="sr-only">
            Type to filter commands. Use arrow keys to navigate, Enter to run, Esc to close.
          </DialogDescription>

          {/* Input row */}
          <div className="flex items-center gap-[10px] px-[14px] py-[12px] border-b border-border">
            <Glyph name="chevron" className="text-primary" />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setFocusedIndex(0);
              }}
              placeholder={placeholder}
              className="flex-1 bg-bg text-text outline-none text-body-sm placeholder:text-dim"
            />
            <span className="text-meta text-dim">{matchCount}</span>
          </div>

          {/* Groups */}
          <div className="max-h-[420px] overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="px-[14px] py-[12px] text-meta text-dim">
                · no commands match
              </div>
            ) : (
              filtered.map((g) => {
                const before = filtered
                  .slice(0, filtered.indexOf(g))
                  .reduce((n, gg) => n + gg.items.length, 0);
                return (
                  <CommandGroupBlock
                    key={g.label}
                    group={g}
                    indexOffset={before}
                    focusedIndex={focusedIndex}
                    onHover={setFocusedIndex}
                    onRun={(item) => {
                      item.onRun();
                      onOpenChange(false);
                    }}
                  />
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="flex justify-between items-center px-[14px] py-[8px] border-t border-border text-meta text-dim">
            <span>
              <Kbd>↑</Kbd>
              <Kbd>↓</Kbd> navigate · <Kbd>↵</Kbd> run · <Kbd>esc</Kbd> close
            </span>
          </div>
        </DialogPrimitive.Content>
      </DialogPortal>
    </DialogPrimitive.Root>
  );
}

function Kbd({ children }: { children: ReactNode }) {
  return (
    <span className="bg-surface-2 text-text-dim px-[5px] py-[1px] mx-[2px]">{children}</span>
  );
}

function CommandGroupBlock({
  group,
  indexOffset,
  focusedIndex,
  onHover,
  onRun,
}: {
  group: CommandGroup;
  indexOffset: number;
  focusedIndex: number;
  onHover: (i: number) => void;
  onRun: (item: CommandItem) => void;
}) {
  return (
    <div className="border-t border-border-dim first:border-t-0 py-[6px]">
      <div className="px-[14px] py-[4px] text-label uppercase text-dim tracking-[0.6px]">
        {group.label}
      </div>
      {group.items.map((item, i) => {
        const absIndex = indexOffset + i;
        const focused = absIndex === focusedIndex;
        return (
          <div
            key={item.id}
            data-focused={focused ? "true" : undefined}
            onMouseEnter={() => onHover(absIndex)}
            onClick={() => onRun(item)}
            className={cn(
              "flex items-center gap-[10px] py-[7px] text-body-sm cursor-pointer",
              focused
                ? "bg-surface text-text border-l-2 border-l-primary pl-[12px] pr-[14px]"
                : "px-[14px] text-text",
            )}
          >
            <span className="flex-1 truncate">{item.label}</span>
            {item.shortcut ? (
              <span className="text-meta text-dim">{item.shortcut}</span>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
