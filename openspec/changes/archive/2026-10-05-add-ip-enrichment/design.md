## Context

Nodes today carry three passive data sources: Shodan (banner, ports, `asn`/`asn_name`, `isp`, `org`, `hostname` — migration `006_add_enrichment_fields`), MaxMind GeoLite2 (`geo_country_*`, and ASN via `src/geoip.py`), and NVD (CVE links). None of them says whether an IP has a history of abuse. The `nodes` table is keyed by `(ip, port)` (unique index `idx_nodes_ip_port`), so one IP can appear in several rows. The local dataset has ~8.3k distinct non-example IPs (640 CRITICAL, 54 MEDIUM, ~7.6k LOW).

Sources evaluated during proposal review:
- **AbuseIPDB** v2 `check`: free tier 1,000 lookups/day, returns `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `lastReportedAt`, `isTor`. Viable: all CRITICAL nodes in one day, the whole dataset in ~9 days.
- **GreyNoise Community**: 50 lookups/week with a key (10/day without), no CVE/tag/actor fields. Rejected.
- **ipinfo**: a third ASN source on top of Shodan + MaxMind. Rejected.
- **Public blocklists** (FireHOL level1, Spamhaus DROP, abuse.ch Feodo Tracker, Tor bulk exit list): bulk text downloads, matched locally. Viable and quota-free.

Precedents reused: `src/nostr/cdn_ranges.py` (download + validated on-disk cache with TTL + atomic write + CIDR matching), `src/nvd/client.py` (HTTP with timeout/retries/backoff), `NostrRelay` (dedicated table keyed by a natural unique key), `ScanJob` + `src/web/background.py` (background job + thread pool), `STALE_THRESHOLD_DAYS` (env-tunable staleness).

## Goals / Non-Goals

**Goals:**
- One reputation record per IP, shared by every node row with that IP, without touching `nodes` columns.
- Pluggable sources: a new source is one module implementing `Enricher` plus one registry entry; its raw payload lands in `sources_json`; the only schema addition is its `<name>_checked_at` column (one nullable column, see decision 7).
- Never exceed a source's quota, across restarts and across CLI/API runs.
- Never enrich example IPs (`is_example=True`).
- Fully offline test suite (all HTTP mocked).

**Non-Goals:**
- GreyNoise, ipinfo, any paid API or scraping.
- Active probing of target IPs.
- Using reputation in `SecurityAnalyzer` risk scoring, or as a node-list filter/column (possible follow-ups once data exists).
- Automatic enrichment as part of `db-import` or scans (enrichment is explicitly triggered).

## Decisions

**1. Dedicated `ip_reputation` table keyed by `ip`, not columns on `nodes`.** Columns on `nodes` would collide with the existing `asn`/`org` names, duplicate data across `(ip, port)` rows, and require a migration per new source. A separate table enriches each IP once and is joined on `nodes.ip` for reads. Schema:
- `ip` (String(45), unique, indexed)
- `abuse_confidence_score` (Integer, nullable), `abuse_total_reports` (Integer, nullable), `abuse_last_reported_at` (DateTime, nullable)
- `blocklists` (JSON-as-Text, list of list ids the IP matched, e.g. `["firehol_level1","feodo"]`; `[]` when checked and clean, null when never checked)
- `sources_json` (Text, JSON: `{source: {status: "ok"|"error"|"skipped", fetched_at, error?, data?}}`)
- `reputation_enriched_at` (DateTime, indexed) — set when at least one source succeeded; drives staleness.
- `first_enriched_at`, `updated_at`.
No FK to `nodes`: reputation outlives node row churn, and the join is on a non-unique column. *Alternative:* prefixed columns on `nodes` (Kimi's option B) — rejected for the reasons above.

**2. Names avoid the existing "enrichment" meaning.** Migration `006_add_enrichment_fields` already means "Shodan host data". The new concept is "reputation": table `ip_reputation`, timestamp `reputation_enriched_at`, env `REPUTATION_STALE_DAYS`. The package is `src/enrichers/` because it is the generic plugin layer.

**3. `Enricher` protocol is batch-shaped.**
```python
class Enricher(Protocol):
    name: str
    def available(self) -> bool: ...                     # key present / lists loadable
    def enrich(self, ips: Sequence[str]) -> Dict[str, SourceResult]: ...
```
Per-IP APIs (AbuseIPDB) loop internally under the quota guard; bulk sources (blocklists) load lists once and match all IPs in memory. A per-IP signature would force blocklists to reload or hold hidden state. `enrich` returns results only for IPs it actually processed; IPs left out because quota ran out are reported back as not attempted, not as errors.

**4. Blocklists as a local-match source.** `blocklists.py` mirrors `cdn_ranges.py`: each list has an id, URL, parser, and validator; payloads are cached under `BLOCKLIST_CACHE_DIR` (default `.blocklist_cache`, gitignored) for 24h, written atomically, and a stale cache is used if a refresh fails. Lists parse into `ipaddress` networks (IPv4 + IPv6); matching uses a sorted-range bisect per address family so ~8k IPs × tens of thousands of CIDRs stays sub-second. Initial lists: `firehol_level1`, `spamhaus_drop`, `feodo`, `tor_exit`. A list that fails with no cache is recorded as `error` for that list and the others still apply. *Alternative:* per-IP DNSBL queries — rejected (one DNS query per IP per list, and they reveal the IP to the DNSBL operator).

**5. AbuseIPDB client.** `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=365` with headers `Key` and `Accept: application/json`, timeout + retry with backoff on 5xx/connection errors (`nvd/client.py` style), project User-Agent. HTTP 429 stops the source for the rest of the run and marks the day's quota as exhausted. HTTP 401/403 (bad or revoked key) also stops the source for the run but does **not** mark the quota exhausted, so a typo can't burn the day's budget and a fixed key works on the next run. Response headers `X-RateLimit-Remaining` are used to correct the local counter downwards if the server reports less remaining than we think.

**6. Persistent quota in `enrichment_quota`.** Rows `(source, day_utc, calls)` with a unique `(source, day_utc)`. Before each AbuseIPDB call the quota module reserves a slot with an atomic conditional `UPDATE … SET calls = calls + 1 WHERE calls < limit AND NOT exhausted` and commits it, so CLI and API runs share one budget without lost increments; a concurrent insert of the day's row (unique `(source, day_utc)`) is caught and treated as already-created. A minimum interval between calls (`ABUSEIPDB_MIN_INTERVAL`, default 1s) throttles bursts. The day resets at 00:00 UTC (AbuseIPDB's reset). *Alternative:* in-memory counter like `credit_tracker.py` — rejected: a crashed or repeated run would re-spend the quota.

**7. Backfill selection and ordering — staleness is per source.** Each source has a `<name>_checked_at` column on `ip_reputation`, set only when that source succeeded for the IP. `ReputationRepository.candidates(limit, stale_days, sources)` selects distinct `nodes.ip` with `is_example = false`, left-joined to `ip_reputation`, where any of the run's *available* sources has a null or older-than-`stale_days` `checked_at`; each candidate carries the list of sources still due, and the service hands each enricher only the IPs it owes (AbuseIPDB quota is never re-spent on an IP it already covers). Ordered by the node's highest risk (CRITICAL → HIGH → MEDIUM → LOW → NULL), then never-enriched first, then oldest. `reputation_enriched_at` (last success of any source) is display-only. *Alternative rejected during review:* a single `reputation_enriched_at` gate — blocklists almost always succeed, so IPs AbuseIPDB skipped (quota, transient error, `--source blocklists` run) silently dropped out of selection for `stale_days`. Example IPs are excluded in SQL **and** re-checked with `is_example_ip()` in the service (defence in depth).

**8. Dry-run is offline.** `--dry-run` runs only the selection query and the quota read, then prints: candidate IPs per risk level, sources available, how many AbuseIPDB calls fit in today's remaining quota, and where the run would stop. It makes no HTTP calls and writes nothing (not even the blocklist cache).

**9. Background job via `ScanJob.job_type`.** Add `job_type` (String(20), not null, default `'scan'`) to `scan_jobs`. `POST /api/v1/enrichment/run` (API key + CSRF, body `{limit?: int ≤ 1000, source?: str}`) creates a `job_type='enrichment'` job; the runner reuses `background.py`'s thread-pool + status-update helpers. Single-flight is per job type, so an enrichment can run alongside a Shodan scan but not alongside another enrichment. Status is read through the existing `GET /api/v1/scans/{job_id}`, which now includes `job_type`. *Alternative:* a separate `EnrichmentJob` model — rejected as duplicate plumbing for an identical state machine.

**10. API shape.** `NodeDetailOut` gains `reputation: Optional[ReputationOut]` (`abuse_confidence_score`, `abuse_total_reports`, `abuse_last_reported_at`, `blocklists`, `reputation_enriched_at`, `stale: bool`, `sources: {name: status}`). Raw `data` payloads are not exposed. The list endpoint `GET /api/v1/nodes` is unchanged (no extra join on the hot path).

**11. Drawer card.** A `REPUTATION` card in the `host` tab, below `host metadata`, hidden when `reputation` is null. Abuse score as a new `Pill` kind `ABUSE` (alert ≥75, warn ≥25, ok <25 — existing tokens), one `BLOCKLIST` pill per hit, total reports, last reported, and `enriched <relative time>` with a `· data may be stale` hint when `stale`. No new design tokens, so both themes work as-is.

## Risks / Trade-offs

- [AbuseIPDB lookups disclose node IPs to a third party] → Documented in the ethical-use docs; the source is opt-in (only active with `ABUSEIPDB_API_KEY`); blocklists disclose nothing.
- [Blocklist licensing/terms] → Only lists published for free reuse are included; ids, URLs and terms are listed in `docs/bitcoin-scanner.md`. Spamhaus DROP restricts some commercial use — note it and keep it removable via config (`BLOCKLISTS` env, comma-separated ids, default all four).
- [FireHOL level1 includes bogons/reserved ranges] → Bitcoin nodes from Shodan are public IPs, so bogon hits should be ~0; if one appears it is itself a data-quality signal, not suppressed.
- [Blocklist and AbuseIPDB data are point-in-time] → `reputation_enriched_at` + `stale` flag; the UI never presents it as live.
- [Quota race if CLI and API run concurrently] → quota increment happens in a DB transaction; API single-flight prevents two API enrichment jobs; a concurrent CLI run can at worst overshoot by the in-flight call, and AbuseIPDB's 429 is the hard backstop.
- [`ScanJob` name now covers non-scan jobs] → accepted; renaming the table is a larger, unrelated migration.
- [AbuseIPDB API terms/fields change] → the client parses defensively (missing fields → null) and stores the raw payload in `sources_json` for later re-parsing.

## Migration Plan

Migration `009_add_ip_reputation.py` (additive): create `ip_reputation` (unique index on `ip`, index on `reputation_enriched_at`), create `enrichment_quota` (unique `(source, day_utc)`), add `scan_jobs.job_type` with server default `'scan'` (existing rows become `scan`). No data backfill in the migration; data arrives via `db-enrich-ips`. Rollback: drop the two tables and the column, unmount the router. Prod (EC2, SQLite) follows the usual Alembic upgrade on deploy.

## Open Questions

- Should reputation eventually feed `SecurityAnalyzer` (e.g. bump risk for Feodo C2 hits)? Deferred until real data shows how often hits occur.
- AbuseIPDB `maxAgeInDays`: 365 chosen for maximum history; revisit if scores look dominated by old reports.
