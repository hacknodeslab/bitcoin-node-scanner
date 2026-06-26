# Nostr Relay CDN-Recon

Measures what fraction of [Nostr](https://nostr.com) relays are hosted **behind a
CDN** (Cloudflare, CloudFront, or Fastly) instead of exposing their origin server
directly. It is a **centralization indicator**: the more relays that depend on a
handful of CDNs, the more fragile and censorable the network becomes.

This is **phase 0** (measurement). Phase 2 — unmasking the real origin IP behind a
CDN — is intentionally out of scope.

> No Shodan credits are used. Classification is pure DNS resolution + CDN CIDR
> matching.

---

## How it works

For each relay host the classifier:

1. **Normalizes** the input — `wss://relay.x/`, `relay.x`, and mixed forms all
   reduce to the bare lowercase hostname. Blank lines and `#` comments are ignored.
2. **Resolves** its A/AAAA addresses via DNS.
3. **Matches** each resolved IP against the published CIDR ranges of the tracked
   CDNs.
4. Emits a **verdict**:

| Verdict | Meaning |
|---------|---------|
| `cloudflare` / `cloudfront` / `fastly` | All resolved IPs fall in that provider's ranges |
| `cloudflare+fastly` (`+`-joined) | IPs span multiple CDNs |
| `direct` | Resolves, but no tracked CDN range matches (origin likely visible) |
| `dns_error` | Host did not resolve |
| `skipped` | `.onion` / `.i2p` host (no DNS to resolve) |

### CDN ranges

Provider IP-range lists are fetched from upstream (Cloudflare, the AWS
`ip-ranges.json` CloudFront entries, and Fastly) and cached on disk for 7 days
(`NOSTR_CDN_CACHE_DIR`, default `.cdn_cache/`). The cache is written atomically and
validated on read, so a truncated or empty file is refetched rather than trusted.
If the live Cloudflare fetch fails (or returns empty), a hardcoded fallback list is
used — Cloudflare is ~99% of real hits, so the headline number stays trustworthy
even fully offline.

---

## Usage

The flow mirrors the Bitcoin scanner: the scanner writes a JSON dump to `output/`;
persistence is a separate step. **The scanner never writes to the database directly.**

```bash
# 1. (optional) Derive a host list from a nostr.watch xlsx export
python -m src.nostr.extract_relays nw-relays.xlsx relays.txt --online --clearnet
#   --online    keep only relays in active rotation (in_rstate=true)
#   --clearnet  drop tor/i2p relays

# 2. Scan — classify every host, write output/nostr_relays_<ts>.json
python -m src.nostr.scanner relays.txt
python -m src.nostr.scanner relays.txt --workers 100 --timeout 4

# 3. Load the dump into the database
python -m src.db.cli db-import-nostr output/nostr_relays_<ts>.json
```

`relays.txt` is one relay URL/host per line. Re-importing **upserts in place** —
one row per host, no duplicates — and the list/stats queries always scope to the
latest scan.

The scanner prints a summary line, e.g.:

```
total=1067 resolved=982 behind_any_cdn=421 (42.9%)
wrote output/nostr_relays_20260625_085546.json
```

---

## API

Both endpoints sit under the shared API-key / CSRF auth (see the
[API reference](API.md)).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/nostr/relays` | Paginated relay list. Filters: `verdict`, `provider`, `behind_cdn`. Total in `X-Total-Count`. |
| GET | `/api/v1/nostr/stats` | Per-verdict counts, per-provider breakdown, total/resolved, and % behind CDN. |

`behind_cdn=true` returns only relays behind a tracked CDN; `behind_cdn=false`
returns the rest (`direct` + `dns_error` + `skipped`). Stats are derived from the
persisted relay rows, so the headline percentage always reconciles with the
per-verdict counts and the relay table.

When no scan has been imported, `/stats` returns a zeroed object and `/relays`
returns an empty page.

---

## Dashboard

The **`/nostr`** panel in the Next.js dashboard renders:

- **Summary cards** — % behind CDN, total / resolved, and a per-provider breakdown.
- **Relay table** — paginated, with the verdict shown as a colour-coded pill,
  plus filters for verdict, provider, and "behind CDN only".
- An **empty state** when no scan has been imported, and an error banner if stats
  fail to load.

---

## Data model

Dedicated tables, fully independent of the Bitcoin `Node` / `Scan` tables (see
[Database Support](DATABASE.md)):

- **`NostrScan`** — one row per import: source list, total, resolved,
  behind-any-CDN count, timestamp, status.
- **`NostrRelay`** — keyed by `host` (unique); stores `verdict`, `providers`,
  `ips`, and `first_seen` / `last_seen`. Indexed on `host`, `verdict`, `last_seen`.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NOSTR_CDN_CACHE_DIR` | `.cdn_cache` | Where CDN IP-range lists are cached (refreshed every 7 days) |
| `OUTPUT_DIR` | `output` | Where the scanner writes its JSON dump |

`extract_relays` needs `openpyxl` (an optional dependency, only used by that helper).
