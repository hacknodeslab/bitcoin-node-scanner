## Why

The scanner tells us *what* a Bitcoin node exposes (version, RPC, CVEs) but not *who else has seen that IP misbehave*. Reputation context — "this CRITICAL node also sits on a known botnet C2 list" or "this IP has 40 abuse reports" — changes how an exposed node should be read, and today the operator has to look it up by hand. Two free, passive, officially published sources cover this well: the AbuseIPDB check API (per-IP score, 1,000 lookups/day) and public IP blocklists (bulk-downloadable, matched locally with zero quota and without disclosing node IPs to anyone).

## What Changes

- **New package `src/enrichers/`** with a pluggable `Enricher` protocol (`name`, `available()`, `enrich(ips)`), so adding a source is one new module plus registration and one `<name>_checked_at` column.
  - `abuseipdb.py` — per-IP lookup against the AbuseIPDB v2 `check` endpoint (abuse confidence score, total reports, last reported at, distinct reporters, `isTor`). Requires `ABUSEIPDB_API_KEY`; skipped cleanly when unset.
  - `blocklists.py` — downloads public blocklists (FireHOL level1, Spamhaus DROP, abuse.ch Feodo Tracker, Tor bulk exit list), caches them on disk with a TTL (same pattern as `src/nostr/cdn_ranges.py`), and matches node IPs locally by CIDR. No API key, no quota, no node IP leaves the host.
  - `quota.py` — persistent per-source daily quota tracker (AbuseIPDB 1,000/day, overridable), plus a minimum inter-request interval.
  - `service.py` — orchestrator: runs every available enricher, isolates per-source failures (log + continue), merges results.
- **New table `ip_reputation`** keyed by unique `ip` (one row per IP, shared by every `(ip, port)` node row): typed columns for the values we filter/render (`abuse_confidence_score`, `abuse_total_reports`, `abuse_last_reported_at`, `blocklists` JSON, per-source `abuseipdb_checked_at` / `blocklists_checked_at`, `reputation_enriched_at`) plus `sources_json` (raw per-source payload + success/failure/timestamp provenance). Additive migration `009`; the `nodes` table is untouched — no collision with the existing Shodan/MaxMind `asn`/`asn_name`/`isp`/`org` columns.
- **New table `enrichment_quota`** persisting per-source, per-day call counts so quota survives restarts and resumable backfills.
- **CLI backfill** `python -m src.db.cli db-enrich-ips` — iterates distinct non-example IPs, prioritized CRITICAL → HIGH → MEDIUM → LOW, skipping, per source, IPs that source checked successfully within `REPUTATION_STALE_DAYS` (default 7); flags `--limit`, `--source`, `--dry-run` (prints the plan and where the quota would stop; makes **no** network calls).
- **API**: `GET /api/v1/nodes/{node_id}` gains an optional `reputation` object (null when the IP was never enriched — backward compatible). New `POST /api/v1/enrichment/run` (API key + CSRF) starts a bounded background enrichment job; reuses `ScanJob` with a new `job_type` discriminator.
- **Filtering**: `GET /api/v1/nodes` gains `blocklisted=true` and `blocklist=<id>`; the query bar accepts the same keys and the command palette gets `node: filter blocklisted (any list)` plus one `node: filter blocklist <id>` per list.
- **Frontend**: the node detail drawer gains a `REPUTATION` card (abuse score pill red ≥75 / amber ≥25 / green <25, blocklist hits as pills, last-enriched time with a stale hint after 7 days), hidden when `reputation` is null.
- **Docs**: rename root `env.example` → `.env.example` (the name `docs/INSTALLATION.md`, `scripts/setup.sh` and `Makefile` already expect) and add the new env vars there, plus `README.md`, `CLAUDE.md`, `docs/bitcoin-scanner.md`; a note in the ethical-use section that AbuseIPDB lookups disclose node IPs to that third party (blocklists do not).

## Capabilities

### New Capabilities
- `ip-enrichment`: pluggable passive IP-reputation enrichment — enricher protocol, AbuseIPDB and blocklist sources, per-source quota, `ip_reputation` persistence, example-IP exclusion, and the `db-enrich-ips` backfill command.

### Modified Capabilities
- `web-api`: node detail payload adds `reputation`; new `POST /api/v1/enrichment/run` endpoint.
- `background-scan`: jobs gain a `job_type` (`scan` | `enrichment`); single-flight applies per job type.
- `dashboard-node-detail-drawer`: new `REPUTATION` card.
- `node-list-filtering`: `blocklisted` / `blocklist` filters on `GET /api/v1/nodes`.
- `dashboard-explorer-view`: query-bar keys `blocklisted`, `blocklist`.
- `dashboard-command-palette`: blocklist filter commands.
- `database-storage`: adds the `ip_reputation` and `enrichment_quota` tables and the `scan_jobs.job_type` column.

## Impact

- **New backend**: `src/enrichers/` (protocol, `abuseipdb.py`, `blocklists.py`, `quota.py`, `service.py`); `src/db/repositories/reputation_repository.py`; `db-enrich-ips` in `src/db/cli.py`; `src/web/routers/enrichment.py` (+ mount in `src/web/main.py`); `src/web/background.py` (enrichment job runner).
- **Modified backend**: `src/db/models.py` (+2 models, `ScanJob.job_type`); `src/web/routers/nodes.py` (`NodeDetailOut.reputation`).
- **DB**: migration `009_add_ip_reputation.py` — additive (two tables + one defaulted column).
- **Frontend**: `frontend/components/explorer/NodeDetailDrawer.tsx` (+ test), `frontend/lib/api/types.ts`.
- **Config**: `ABUSEIPDB_API_KEY`, `ABUSEIPDB_DAILY_QUOTA` (default `1000`), `REPUTATION_STALE_DAYS` (default `7`), `BLOCKLIST_CACHE_DIR` (default `.blocklist_cache`, gitignored).
- **Untouched**: Shodan scanner, NVD matcher, `nodes` table columns.
- **Out of scope (non-goals)**: GreyNoise (free tier is 50 lookups/week with no CVE data — not viable); ipinfo or any third ASN source (Shodan + MaxMind already cover ASN); any active probing of target IPs; paid APIs or scraping; a reputation column in the node table or reputation-based risk scoring (follow-ups).
