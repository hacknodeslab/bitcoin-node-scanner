/**
 * Theme runtime helpers.
 *
 * Two responsibilities:
 *   1. `resolveTheme` correctness over the (stored, system) input matrix.
 *   2. `THEME_INIT_SCRIPT` (the inline FOUC mitigation IIFE) stays
 *      behaviourally identical to `resolveTheme` — drift between the two
 *      would re-introduce the wrong-theme flash this script exists to prevent.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  THEME_INIT_SCRIPT,
  THEME_STORAGE_KEY,
  isThemeMode,
  readStoredTheme,
  resolveTheme,
  writeStoredTheme,
  type ResolvedTheme,
  type ThemeMode,
} from "../theme";

const STORED_INPUTS: (ThemeMode | null)[] = ["dark", "light", "system", null];
const SYSTEM_INPUTS: boolean[] = [true, false];

describe("resolveTheme", () => {
  for (const stored of STORED_INPUTS) {
    for (const sysDark of SYSTEM_INPUTS) {
      const expected: ResolvedTheme =
        stored === "dark"
          ? "dark"
          : stored === "light"
            ? "light"
            : sysDark
              ? "dark"
              : "light";
      it(`stored=${stored ?? "null"} systemPrefersDark=${sysDark} → ${expected}`, () => {
        expect(resolveTheme(stored, sysDark)).toBe(expected);
      });
    }
  }
});

describe("isThemeMode", () => {
  it("accepts the three modes", () => {
    expect(isThemeMode("dark")).toBe(true);
    expect(isThemeMode("light")).toBe(true);
    expect(isThemeMode("system")).toBe(true);
  });
  it("rejects unknown values", () => {
    expect(isThemeMode("auto")).toBe(false);
    expect(isThemeMode("")).toBe(false);
    expect(isThemeMode(null)).toBe(false);
    expect(isThemeMode(undefined)).toBe(false);
    expect(isThemeMode(42)).toBe(false);
  });
});

describe("readStoredTheme / writeStoredTheme", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("returns null when no value is stored", () => {
    expect(readStoredTheme()).toBeNull();
  });

  it("round-trips a valid mode", () => {
    expect(writeStoredTheme("light")).toBe(true);
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(readStoredTheme()).toBe("light");
  });

  it("returns null on garbage stored value", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "AUTO");
    expect(readStoredTheme()).toBeNull();
  });

  it("readStoredTheme swallows getItem throws (privacy mode)", () => {
    const spy = vi
      .spyOn(Storage.prototype, "getItem")
      .mockImplementation(() => {
        throw new Error("denied");
      });
    expect(readStoredTheme()).toBeNull();
    spy.mockRestore();
  });

  it("writeStoredTheme returns false on quota exceeded", () => {
    const spy = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new Error("QuotaExceededError");
      });
    expect(writeStoredTheme("dark")).toBe(false);
    spy.mockRestore();
  });
});

describe("THEME_INIT_SCRIPT parity with resolveTheme", () => {
  // Run the inline script in a sandboxed scope with fakes for window/document
  // /localStorage, then assert the painted data-theme matches resolveTheme's
  // output for the same inputs.
  type Painted = "dark" | "light";

  function runInitScript(stored: ThemeMode | null, sysDark: boolean): Painted {
    const fakeStorage = new Map<string, string>();
    if (stored !== null) fakeStorage.set(THEME_STORAGE_KEY, stored);

    let painted: Painted | null = null;
    const fakeWindow = {
      localStorage: {
        getItem: (k: string) => (fakeStorage.has(k) ? fakeStorage.get(k)! : null),
      },
      matchMedia: (q: string) => ({
        matches: q === "(prefers-color-scheme: dark)" ? sysDark : false,
      }),
    };
    const fakeDocument = {
      documentElement: {
        setAttribute: (name: string, value: string) => {
          if (name === "data-theme") painted = value as Painted;
        },
      },
    };

    const fn = new Function("window", "document", THEME_INIT_SCRIPT);
    fn(fakeWindow, fakeDocument);
    return painted!;
  }

  for (const stored of STORED_INPUTS) {
    for (const sysDark of SYSTEM_INPUTS) {
      it(`script(stored=${stored ?? "null"}, sysDark=${sysDark}) === resolveTheme`, () => {
        const expected = resolveTheme(stored, sysDark);
        expect(runInitScript(stored, sysDark)).toBe(expected);
      });
    }
  }

  it("script swallows localStorage throws and falls back to system preference", () => {
    let painted: string | null = null;
    const fakeWindow = {
      localStorage: {
        getItem: () => {
          throw new Error("denied");
        },
      },
      matchMedia: () => ({ matches: true }),
    };
    const fakeDocument = {
      documentElement: {
        setAttribute: (name: string, value: string) => {
          if (name === "data-theme") painted = value;
        },
      },
    };
    const fn = new Function("window", "document", THEME_INIT_SCRIPT);
    expect(() => fn(fakeWindow, fakeDocument)).not.toThrow();
    expect(painted).toBe("dark");
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
