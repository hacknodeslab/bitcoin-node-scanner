import { TopNav } from "@/components/explorer/TopNav";
import { QueryBar } from "@/components/ui/QueryBar";
import { StatsStrip } from "@/components/explorer/StatsStrip";
import { NodeTablePlaceholder } from "@/components/explorer/NodeTablePlaceholder";
import { ExplorerFooter } from "@/components/explorer/ExplorerFooter";

/**
 * Explorer view (§8.1 layout). Composes the five strips: top nav, query bar,
 * stats strip, table, footer. The QueryBar is rendered with an empty value
 * for now — the input controller and grammar wiring lands in §8.2; the table
 * and the scan trigger arrive in §8.4 / §8.5.
 *
 * StatsStrip is the only live consumer at this stage — it pulls real
 * /api/v1/stats data via `useStats`.
 */
export default function ExplorerPage() {
  return (
    <div className="min-h-screen flex flex-col">
      <TopNav />
      <QueryBar query="" />
      <StatsStrip />
      <main className="flex-1">
        <NodeTablePlaceholder />
      </main>
      <ExplorerFooter />
    </div>
  );
}
