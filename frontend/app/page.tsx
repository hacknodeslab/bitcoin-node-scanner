import { TopNav } from "@/components/explorer/TopNav";
import { QueryBar } from "@/components/ui/QueryBar";
import { StatsStrip } from "@/components/explorer/StatsStrip";
import { NodeTable } from "@/components/explorer/NodeTable";
import { ExplorerFooter } from "@/components/explorer/ExplorerFooter";

/**
 * Explorer view (§8.1 layout). Composes the five strips: top nav, query bar,
 * stats strip, table, footer. The QueryBar is rendered with an empty value
 * for now — the input controller and grammar wiring lands in §8.2; the scan
 * trigger arrives in §8.5.
 *
 * Live consumers at this stage: StatsStrip (`useStats`), NodeTable
 * (`useNodes`).
 */
export default function ExplorerPage() {
  return (
    <div className="min-h-screen flex flex-col">
      <TopNav />
      <QueryBar query="" />
      <StatsStrip />
      <main className="flex-1">
        <NodeTable />
      </main>
      <ExplorerFooter />
    </div>
  );
}
