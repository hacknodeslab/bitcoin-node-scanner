/**
 * Shared Nostr CDN-recon verdict logic — the single frontend source of truth.
 * Mirrors `NON_CDN_VERDICTS` in `src/nostr/classifier.py`; keep them in sync.
 * (Per-provider counts are derived server-side and exposed on the stats
 * endpoint, so the frontend never re-parses verdict strings.)
 */

/** Verdicts that mean a relay is NOT behind a tracked CDN. */
export const NON_CDN_VERDICTS = new Set(["direct", "dns_error", "skipped"]);
