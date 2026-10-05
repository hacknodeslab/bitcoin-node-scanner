/**
 * Public lookup page for each blocklist id emitted by `src/enrichers/blocklists.py`.
 * Opening one is a user action in their own browser, so the IP goes to that
 * site only when they click. FireHOL has no per-IP lookup, so it links to the
 * list's own page. Unknown ids get no link.
 */
/** Blocklist ids the backend can report (keep in sync with BLOCKLISTS in src/enrichers/blocklists.py). */
export const BLOCKLIST_IDS = ["firehol_level1", "spamhaus_drop", "feodo", "tor_exit"] as const;

export function isBlocklistId(value: string): boolean {
  return (BLOCKLIST_IDS as readonly string[]).includes(value);
}

const LOOKUP_URLS: Record<string, (ip: string) => string> = {
  spamhaus_drop: (ip) => `https://check.spamhaus.org/results/?query=${encodeURIComponent(ip)}`,
  feodo: (ip) => `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(ip)}/`,
  tor_exit: (ip) => `https://metrics.torproject.org/rs.html#search/${encodeURIComponent(ip)}`,
  firehol_level1: () => "https://iplists.firehol.org/?ipset=firehol_level1",
};

export function blocklistLookupUrl(list: string, ip: string): string | null {
  const build = LOOKUP_URLS[list];
  return build ? build(ip) : null;
}
