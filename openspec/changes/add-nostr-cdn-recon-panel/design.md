## Context

`../nostr-cf-recon` is a standalone PoC: `check_cf.py` reads a relay host list, resolves A/AAAA records in parallel (`ThreadPoolExecutor`, 50 workers, 5s timeout), and classifies each host against the published CIDR ranges of Cloudflare/CloudFront/Fastly (cached 7 days under `.cdn_cache/`, with a hardcoded Cloudflare fallback). It prints a summary table and an optional JSON dump (`{counts, total, resolved, behind_any_cdn, results[]}`). Phase-2 origin unmasking is explicitly out of scope there, and stays out of scope here.

This repo already has a proven shape for "add a panel": **scanner → JSON in `output/` → `db-import` to SQLAlchemy → `repositories/` → FastAPI router under `/api/v1/*` → Next.js page in `frontend/app/` + a `NAV_LINKS` entry in `TopNav`**. The most recent precedent is the `vulnerabilities` page. Bitcoin scans deliberately do **not** persist directly from the scanner — they write JSON and are loaded by an explicit `db-import` step. The Nostr panel mirrors all of this.

Two toolchains: Python (`src/`) on FastAPI `:8000`, Next.js (`frontend/`) on `:3000`. Auth is API-key + CSRF (`src/web/auth.py`). DB is SQLAlchemy 2.0, SQLite default / PostgreSQL optional.

## Goals / Non-Goals

**Goals:**
- Port the phase-0 CDN-classification logic into `src/nostr/` without losing the credit-free, DNS-only nature of the PoC.
- Persist scans + relays to **dedicated** tables so Nostr data never contaminates the `Node`/`Scan`/CVE schema.
- Expose `/api/v1/nostr/relays` (paginated, filterable) and `/api/v1/nostr/stats` (aggregates) behind the existing auth.
- Ship a dashboard page that tells the centralization story (% behind CDN, Cloudflare dominance) and lets the user filter by verdict/provider.
- Keep ingestion manual (JSON → `db-import-nostr`), identical in spirit to the Bitcoin flow.

**Non-Goals:**
- Phase-2 origin unmasking (NIP-11 fingerprint, DNS history, Censys/Shodan, `--resolve` validation).
- Auto-fetching the relay list from the nostr.watch API (the operator supplies a list/xlsx).
- CDNs without a public IP list (Akamai and similar).
- Reusing `Node`/`Scan` tables for relays.

## Decisions

**1. Dedicated `nostr/` module rather than folding into `scanner.py`.** Bitcoin scanning is Shodan-credit-bound and risk-analyzer-driven; Nostr recon is pure DNS + CIDR matching with no credits. Keeping them separate avoids coupling the credit-tracker/optimizer machinery to a feature that needs none of it. The CDN-range fetch/cache lives in `src/nostr/cdn_ranges.py`; classification in `src/nostr/classifier.py`; the runnable entrypoint in `src/nostr/scanner.py`. *Alternative considered:* a generic "recon" abstraction over both — rejected as premature; the two share almost no logic.

**2. Dedicated tables `nostr_relays` + `nostr_scans`.** A relay is keyed by **host** (a DNS name), not `(ip, port)` like a Bitcoin node, and carries verdict/provider semantics that have no analog on `Node`. A discriminator column on `Node` would force nullable Bitcoin-only and Nostr-only columns to coexist and break the existing indexes/filters. *Alternative considered:* reuse `Node` with a `kind` flag — rejected (see Risks). Additive migration only; no change to node/CVE tables.

**3. Manual JSON-import ingestion (`db-import-nostr`), mirroring `db-import`.** Matches the established "scanner writes JSON, CLI loads it" contract and keeps scan execution decoupled from DB writes (re-importable, inspectable artifacts in `output/`). *Alternative considered:* persist directly from the scanner — rejected for consistency with the Bitcoin flow and to keep the scanner side-effect-free.

**4. Verdict modeled as a string, providers as a JSON list.** The PoC already emits combination verdicts (`"cloudflare+fastly"`) and a `providers[]` array. Store `verdict: str` (single value, matching the PoC's `"+"-join` for multi-CDN) plus `providers: JSON` and `ips: JSON` for fidelity. Filtering by `provider` queries membership in `providers`; filtering by `behind_cdn` is `verdict NOT IN ('direct','dns_error','skipped')`. *Alternative considered:* a normalized relay↔provider junction table — rejected as overkill for a handful of providers and a read-mostly panel.

**5. Stats computed in the repository, not the router.** `GET /api/v1/nostr/stats` returns counts-per-verdict, total, resolved, `behind_any_cdn`, and percentages from a single `GROUP BY` over the latest scan's relays (mirroring how `stats.py` aggregates nodes). Keeps the router thin and the math testable.

**6. Frontend reuses the design system wholesale.** Verdict renders via the existing `Pill` component (a new `kind`/variant mapping for CDN verdicts → token colors); the table/pagination reuse `NodeTable` patterns; summary cards reuse DESIGN.md tokens and work in dark/light. A `nostr` entry is added to `NAV_LINKS` in `TopNav`, and the `current` union type gains `"nostr"`.

## Risks / Trade-offs

- **CDN ranges drift / live fetch fails** → 7-day cache + hardcoded Cloudflare fallback (already in the PoC). Cloudflare is ~99% of hits, so the fallback alone keeps the headline number meaningful even fully offline.
- **DNS resolution is environment-dependent** (the importing/scanning host's resolver affects results) → results are snapshotted per `NostrScan` with a timestamp; the panel shows the latest scan and never claims real-time accuracy.
- **Reusing `Node` would have been fewer tables** → rejected: it mixes two domains, forces nullable columns, and complicates the existing node filters/indexes. Two small additive tables are cheaper long-term.
- **Verdict-as-string vs. junction table** → string + JSON `providers` is denormalized, but the panel is read-mostly and provider cardinality is tiny; a junction table buys nothing here.
- **Scope creep toward phase 2** → explicitly fenced off in Non-Goals; the schema (storing resolved `ips`) leaves room for a future unmasking pass without forcing it now.

## Migration Plan

Additive only: create `nostr_relays` and `nostr_scans`. No backfill, no changes to existing tables, so rollback is dropping the two new tables and removing the router mount. Follows the same migration approach as prior table-adding changes in `database-storage`.
