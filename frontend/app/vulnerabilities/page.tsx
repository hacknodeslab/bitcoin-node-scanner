import { TopNav } from "@/components/explorer/TopNav";
import { VulnerabilitiesView } from "@/components/vulnerabilities/VulnerabilitiesView";

/**
 * CVE catalog view. The page composes the static TopNav above the
 * client-side `VulnerabilitiesView`, which owns sort/pagination/expand
 * state and fetches the catalog via SWR.
 */
export default function VulnerabilitiesPage() {
  return (
    <div className="h-[100dvh] flex flex-col">
      <TopNav current="vulnerabilities" />
      <VulnerabilitiesView />
    </div>
  );
}
