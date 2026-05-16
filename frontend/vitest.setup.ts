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
