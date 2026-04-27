"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  THEME_MODES,
  readStoredTheme,
  resolveTheme,
  systemPrefersDark,
  writeStoredTheme,
  type ResolvedTheme,
  type ThemeMode,
} from "@/lib/theme";

interface ThemeContextValue {
  mode: ThemeMode;
  resolved: ResolvedTheme;
  setMode: (next: ThemeMode) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function applyResolved(resolved: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-theme", resolved);
}

/**
 * Owns the active theme mode. The pre-hydration script in `app/layout.tsx`
 * sets `<html data-theme>` before React mounts, so the provider's first
 * render is in agreement with the painted attribute. We read the stored
 * mode synchronously here so SSR and CSR diverge only on the resolved value
 * — never on the rendered DOM, which is theme-agnostic.
 *
 * The `matchMedia` listener is only mounted while `mode === "system"` so
 * explicit dark/light selections are never overridden by an OS flip.
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => readStoredTheme() ?? "system");
  const [resolved, setResolved] = useState<ResolvedTheme>(() =>
    resolveTheme(readStoredTheme(), systemPrefersDark()),
  );

  const setMode = useCallback((next: ThemeMode) => {
    writeStoredTheme(next);
    const resolvedNext = resolveTheme(next, systemPrefersDark());
    applyResolved(resolvedNext);
    setModeState(next);
    setResolved(resolvedNext);
  }, []);

  // Track OS preference only while in "system" mode.
  useEffect(() => {
    if (mode !== "system") return;
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (event: MediaQueryListEvent) => {
      const next: ResolvedTheme = event.matches ? "dark" : "light";
      applyResolved(next);
      setResolved(next);
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [mode]);

  // Sync the resolved attribute on first mount (covers the case where the
  // pre-hydration script was skipped — e.g. JS-disabled SSR snapshot —
  // and ensures the provider's state matches the painted attribute).
  useEffect(() => {
    applyResolved(resolved);
  }, [resolved]);

  const value = useMemo<ThemeContextValue>(
    () => ({ mode, resolved, setMode }),
    [mode, resolved, setMode],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within <ThemeProvider>");
  return ctx;
}

export const THEME_OPTIONS: readonly ThemeMode[] = THEME_MODES;
