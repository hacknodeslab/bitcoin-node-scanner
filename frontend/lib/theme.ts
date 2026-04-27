/**
 * Theme runtime helpers.
 *
 * Three modes — `dark`, `light`, `system`. The dashboard exposes the active
 * mode through `<html data-theme="dark|light">`; CSS variables in
 * `globals.css` swap on that attribute, so component code stays palette-agnostic.
 *
 * `THEME_INIT_SCRIPT` is the inline IIFE injected via Next's
 * <Script strategy="beforeInteractive"> in `app/layout.tsx`. It runs before
 * React hydrates and prevents the flash of wrong theme. It MUST stay
 * behaviourally identical to `resolveTheme` — `lib/__tests__/theme.test.ts`
 * exercises both against the same input matrix.
 */

export type ThemeMode = "dark" | "light" | "system";
export type ResolvedTheme = "dark" | "light";

export const THEME_STORAGE_KEY = "bns:theme";
export const THEME_MODES: readonly ThemeMode[] = ["dark", "light", "system"] as const;

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === "dark" || value === "light" || value === "system";
}

export function resolveTheme(
  stored: ThemeMode | null,
  systemPrefersDark: boolean,
): ResolvedTheme {
  const mode: ThemeMode = stored ?? "system";
  if (mode === "dark") return "dark";
  if (mode === "light") return "light";
  return systemPrefersDark ? "dark" : "light";
}

export function readStoredTheme(): ThemeMode | null {
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeMode(raw) ? raw : null;
  } catch {
    return null;
  }
}

export function writeStoredTheme(mode: ThemeMode): boolean {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, mode);
    return true;
  } catch {
    return false;
  }
}

export function systemPrefersDark(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/**
 * Inline pre-hydration script. Behavioural mirror of `resolveTheme` — keep
 * them in sync. Sets `<html data-theme>` synchronously before React mounts.
 */
export const THEME_INIT_SCRIPT = `(function(){try{var k="${THEME_STORAGE_KEY}";var s=null;try{var v=window.localStorage.getItem(k);if(v==="dark"||v==="light"||v==="system")s=v;}catch(e){}var m=s||"system";var d=m==="dark"||(m==="system"&&window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.setAttribute("data-theme",d?"dark":"light");}catch(e){}})();`;
