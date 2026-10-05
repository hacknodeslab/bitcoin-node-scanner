import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// `next/navigation` is server-aware and reads request context that doesn't
// exist under jsdom — provide minimal stubs so client components that call
// `useRouter()` render under test.
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
  }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
}));

// Node ≥25 ships a stubbed global `localStorage`/`sessionStorage`/`Storage`
// (disabled unless --localstorage-file is passed); vitest's populateGlobal
// copies the stubs over jsdom's working ones, leaving `window.localStorage`
// undefined and `Storage.prototype` unspyable. Restore all three from a
// fresh jsdom window so instances and constructor stay consistent.
// @ts-expect-error jsdom has no bundled types; test setup only.
import { JSDOM } from "jsdom";

const storageDom = new JSDOM("", { url: "http://localhost:3000/" });

if (typeof window.localStorage === "undefined") {
  for (const name of ["localStorage", "sessionStorage"] as const) {
    Object.defineProperty(window, name, {
      value: storageDom.window[name],
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, name, {
      value: storageDom.window[name],
      configurable: true,
      writable: true,
    });
  }
  Object.defineProperty(globalThis, "Storage", {
    value: storageDom.window.Storage,
    configurable: true,
    writable: true,
  });
}
