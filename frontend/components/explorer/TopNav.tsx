import Link from "next/link";
import { Brand } from "@/components/brand/Brand";
import { Glyph } from "@/components/ui/Glyph";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "./ThemeToggle";

const NAV_LINKS = [
  { key: "explorer", label: "explorer", href: "/" },
  { key: "vulnerabilities", label: "vulnerabilities", href: "/vulnerabilities" },
  { key: "nostr", label: "nostr", href: "/nostr" },
] as const;

/**
 * Top navigation strip: brand mark and route links on the left, theme
 * toggle in the middle, command-palette hint on the right. The ⌘K listener
 * and palette UI live in `CommandPaletteRoot` — here we render the
 * affordance only. `current` highlights the active route.
 */
export function TopNav({ current }: { current?: "explorer" | "vulnerabilities" | "nostr" }) {
  return (
    <header
      className="flex items-center justify-between px-[14px] py-[10px] border-b border-border"
      data-testid="top-nav"
    >
      <div className="flex items-center gap-[16px]">
        <Brand />
        <nav className="flex items-center gap-[12px] text-meta" data-testid="top-nav-links">
          {NAV_LINKS.map((l) => (
            <Link
              key={l.key}
              href={l.href}
              aria-current={current === l.key ? "page" : undefined}
              className={cn(
                "uppercase tracking-[0.5px]",
                current === l.key ? "text-text" : "text-dim hover:text-text-dim",
              )}
            >
              {l.label}
            </Link>
          ))}
        </nav>
      </div>
      <ThemeToggle />
      <div className="flex items-center gap-[6px] text-meta text-muted">
        <Glyph name="cmd" />
        <span>K</span>
        <span className="text-dim">·</span>
        <span>palette</span>
      </div>
    </header>
  );
}
