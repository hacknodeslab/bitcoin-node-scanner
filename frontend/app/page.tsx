import { TopNav } from "@/components/explorer/TopNav";
import { StatsStrip } from "@/components/explorer/StatsStrip";
import { Explorer } from "@/components/explorer/Explorer";
import { ExplorerFooter } from "@/components/explorer/ExplorerFooter";

/**
 * Explorer view. Composes the static top strips (nav, stats) around the
 * client-side `Explorer` (which owns the applied query string and lifts
 * filters into the node table). The scan trigger arrives in §8.5.
 *
 * Live consumers: StatsStrip (`useStats`), Explorer → NodeTable (`useNodes`)
 * + QueryBarController (parses the grammar into NodeListParams via
 * `parseQueryToFilters`).
 */
export default function ExplorerPage() {
  return (
    <div className="min-h-screen flex flex-col">
      <TopNav />
      <StatsStrip />
      <main className="flex-1">
        <Explorer />
      </main>
      <ExplorerFooter />
    </div>
  );
}
