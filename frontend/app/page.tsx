import { TopNav } from "@/components/explorer/TopNav";
import { StatsStrip } from "@/components/explorer/StatsStrip";
import { Explorer } from "@/components/explorer/Explorer";

/**
 * Explorer view. The page is a server component composing the static top
 * strips (nav, stats) above the client-side `Explorer`, which owns the
 * applied query, the scan-job hook, the node table, the footer, and the
 * ⌘K command palette. Keeping the footer + palette inside Explorer lets
 * them share the single useScanJob instance via context.
 *
 * Live consumers: StatsStrip (`useStats`), Explorer → NodeTable
 * (`useNodes`) + QueryBarController (`parseQueryToFilters`) +
 * ExplorerFooter (`useScanJob`) + CommandPaletteRoot (⌘K listener).
 */
export default function ExplorerPage() {
  // h-[100dvh] (not min-h-screen) so the explorer fits the viewport: the
  // table region scrolls internally and the footer stays pinned. `min-h-0`
  // on flex children that should shrink is applied inside Explorer.
  return (
    <div className="h-[100dvh] flex flex-col">
      <TopNav />
      <StatsStrip />
      <Explorer />
    </div>
  );
}
