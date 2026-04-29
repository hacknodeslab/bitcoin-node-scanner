"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
} from "react";
import {
  THEME_MODES,
  THEME_STORAGE_KEY,
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

// Same-tab `setMode` calls write to localStorage and notify these listeners
// so `useSyncExternalStore` re-reads. Cross-tab updates arrive via `storage`.
const modeListeners = new Set<() => void>();

function subscribeMode(callback: () => void): () => void {
  modeListeners.add(callback);
  if (typeof window === "undefined") {
    return () => {
      modeListeners.delete(callback);
    };
  }
  const onStorage = (event: StorageEvent) => {
    if (event.key === THEME_STORAGE_KEY) callback();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    modeListeners.delete(callback);
    window.removeEventListener("storage", onStorage);
  };
}

function getModeSnapshot(): ThemeMode {
  return readStoredTheme() ?? "system";
}

function getServerModeSnapshot(): ThemeMode {
  return "system";
}

function subscribeSystemDark(callback: () => void): () => void {
  if (typeof window === "undefined" || !window.matchMedia) return () => {};
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  mq.addEventListener("change", callback);
  return () => mq.removeEventListener("change", callback);
}

function getSystemDarkSnapshot(): boolean {
  return systemPrefersDark();
}

function getServerSystemDarkSnapshot(): boolean {
  return true;
}

/**
 * Owns the active theme mode. The pre-hydration script in `app/layout.tsx`
 * sets `<html data-theme>` before React mounts, so colours paint correctly
 * from the first frame. We use `useSyncExternalStore` so the SSR snapshot
 * (`mode = "system"`, `systemDark = true`) matches the painted HTML and the
 * client transitions to the real values after hydration without setState-
 * in-effect cascading renders.
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const mode = useSyncExternalStore(
    subscribeMode,
    getModeSnapshot,
    getServerModeSnapshot,
  );
  const systemDark = useSyncExternalStore(
    subscribeSystemDark,
    getSystemDarkSnapshot,
    getServerSystemDarkSnapshot,
  );
  const resolved = resolveTheme(mode, systemDark);

  const setMode = useCallback((next: ThemeMode) => {
    writeStoredTheme(next);
    modeListeners.forEach((cb) => cb());
  }, []);

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
