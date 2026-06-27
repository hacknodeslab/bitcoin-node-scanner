import { TopNav } from "@/components/explorer/TopNav";
import { NostrView } from "@/components/nostr/NostrView";

/**
 * Nostr relay CDN-recon panel. Composes the static TopNav above the
 * client-side `NostrView`, which owns filter/pagination state and fetches
 * the latest scan's relays + stats via SWR.
 */
export default function NostrPage() {
  return (
    <div className="h-[100dvh] flex flex-col">
      <TopNav current="nostr" />
      <NostrView />
    </div>
  );
}
