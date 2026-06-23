## Why

The scanner analyzes exposure of **Bitcoin nodes**, but its underlying thesis is broader: measuring the **centralization and infrastructure exposure of networks that market themselves as decentralized**. The `nostr-cf-recon` PoC (phase 0) proved with real data that **~28% of active Nostr relays sit behind a CDN — almost entirely Cloudflare** (301/1067 resolved hosts from the nostr.watch 2026-05 export). A single Cloudflare event (outage, regional block, moderation decision) therefore hits a large slice of the Nostr ecosystem at once, despite there being "technically" hundreds of distinct relays.

That finding belongs in the dashboard, but today it lives as a loose script (`check_cf.py`) that prints JSON and is lost. There is no persistence, no API, no way to view it alongside the rest of the recon. This change promotes it to a **first-class panel** inside the scanner, reusing the exact pattern already proven by the `vulnerabilities` page: scanner → JSON → `db-import` → repositories → FastAPI router → Next.js page + a `TopNav` link.

## What Changes

- **New backend module `src/nostr/`** porting `check_cf.py`: host normalization (`wss://relay.x/` → `relay.x`), parallel A/AAAA resolution, and classification of each relay against the published CIDR ranges of Cloudflare / CloudFront / Fastly (live fetch + 7-day cache, with a hardcoded Cloudflare fallback). Verdicts: `cloudflare`, `cloudfront`, `fastly`, combinations, `direct`, `dns_error`, `skipped` (for `.onion`/`.i2p`).
- **Scan + ingest flow mirroring the Bitcoin scanner**: `python -m src.nostr.scanner <relays.txt>` writes a JSON dump to `output/` (same `{counts, total, resolved, behind_any_cdn, results[]}` shape as the PoC); a new CLI command `db-import-nostr <dump.json>` persists it. Relay lists are supplied **manually** (the Bitcoin scanner likewise does not auto-fetch). Ships the `extract_relays.py` helper that derives a host list from a nostr.watch xlsx export.
- **Dedicated Nostr tables** (separate from `Node`/`Scan`): `NostrRelay` (host, verdict, providers, resolved IPs, first/last seen; indexes on `host`, `verdict`, `last_seen`) and `NostrScan` (session: source list, totals, `behind_any_cdn`, timestamp, status).
- **API**: new router `GET /api/v1/nostr/relays` (paginated, filterable by `verdict` / `provider` / `behind_cdn`) and `GET /api/v1/nostr/stats` (aggregates: counts per verdict, % behind CDN, Cloudflare dominance, total/resolved). Reuses the existing API-key + CSRF auth.
- **Frontend — new route `frontend/app/nostr/page.tsx`**: summary cards (% behind CDN, per-provider breakdown) + a sortable/paginated relay table (host, verdict as `Pill`, providers, IPs). Reuses DESIGN.md tokens, dark/light theme, and the table/pagination patterns from `NodeTable`. Adds a `nostr` entry to `NAV_LINKS` in `TopNav`.

## Capabilities

### New Capabilities
- `nostr-cdn-recon`: engine that classifies Nostr relays by CDN presence (resolve → CIDR match → verdict) and persists scans/relays to dedicated tables via a manual JSON-import flow.
- `dashboard-nostr-view`: dashboard page that surfaces relay-behind-CDN centralization, with verdict/provider filtering and per-provider summary stats.

### Modified Capabilities
- `web-api`: adds the `/api/v1/nostr/*` endpoint group (`relays`, `stats`).
- `database-storage`: adds the `nostr_relays` and `nostr_scans` tables (additive; no change to node/CVE tables).

## Impact

- **New backend**: `src/nostr/` (scanner, classifier, CDN-range cache); `src/db/models.py` (+2 models); `src/db/repositories/nostr_repository.py`; `src/web/routers/nostr.py` (+ wiring in `src/web/main.py`); `src/db/cli.py` (`db-import-nostr` command).
- **New frontend**: `frontend/app/nostr/page.tsx` + supporting components; `frontend/lib/api/endpoints.ts` / `types.ts` (Nostr relay + stats types); a `nostr` link in `frontend/components/explorer/TopNav.tsx`.
- **DB**: additive migration (two new tables). Does not touch the node/CVE schema.
- **Docs**: `CLAUDE.md` (Nostr scan flow + new CLI command) and a short usage note.
- **Out of scope (non-goals)**: phase-2 origin unmasking (NIP-11 fingerprint, DNS history, Censys/Shodan, `--resolve` validation); auto-fetching the relay list from the nostr.watch API; CDNs without a public IP list (e.g. Akamai).
