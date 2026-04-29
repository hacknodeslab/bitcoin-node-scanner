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
 * sets `<html data-theme>` before React mounts, so colours paint correctly
 * from the first frame. React state, however, must hydrate to the SSR-rendered
 * default ("system") to avoid a hydration mismatch — we sync to the actual
 * stored mode in a mount effect.
 *
 * The `matchMedia` listener is only mounted while `mode === "system"` so
 * explicit dark/light selections are never overridden by an OS flip.
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>("system");
  const [resolved, setResolved] = useState<ResolvedTheme>("dark");

  const setMode = useCallback((next: ThemeMode) => {
    writeStoredTheme(next);
    const resolvedNext = resolveTheme(next, systemPrefersDark());
    applyResolved(resolvedNext);
    setModeState(next);
    setResolved(resolvedNext);
  }, []);

  // Hydrate from localStorage post-mount to keep SSR and CSR in agreement.
  useEffect(() => {
    const stored = readStoredTheme() ?? "system";
    const resolvedNext = resolveTheme(stored, systemPrefersDark());
    setModeState(stored);
    setResolved(resolvedNext);
    applyResolved(resolvedNext);
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
