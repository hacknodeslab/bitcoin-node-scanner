## Context

The Node model already has `country_code`, `country_name`, `city`, `latitude`, `longitude`, `asn`, `asn_name`. These are populated from Shodan's API response in `scanner.py` (lines 190–194) and forwarded to the DB via `scanner_integration.py` (lines 92–96). The gap: coordinates and city are frequently null, and there is no way to re-enrich existing rows without re-running a full Shodan scan.

MaxMind GeoLite2 provides three separate `.mmdb` files:
- **GeoLite2-Country.mmdb** — country ISO code and name
- **GeoLite2-City.mmdb** — city, subdivision (region/state), postal code, lat/lon (covers country too)
- **GeoLite2-ASN.mmdb** — ASN number and organization name

The `geoip2` Python library (`geoip2.database.Reader`) reads these files efficiently in-process with no network calls.

## Goals / Non-Goals

**Goals:**
- Reliable city + coordinates for every node, regardless of Shodan data quality
- Offline enrichment (no API calls at runtime)
- Retroactive enrichment of all existing DB rows via CLI command
- New `subdivision` field on Node for region/state data
- Web API endpoint exposing full geo detail for a single node

**Non-Goals:**
- Paid MaxMind GeoIP2 databases (GeoLite2 free tier is sufficient)
- Replacing Shodan-provided geo data — MaxMind fills gaps only
- Auto-downloading `.mmdb` files at startup (user must run download script)
- IPv6 support in the first iteration (GeoLite2 supports it but scanner currently targets IPv4)

## Decisions

### 1. `GeoIPService` as a thin wrapper, injected where needed

A single `src/geoip.py` module with `GeoIPService(db_dir)` encapsulates all MaxMind logic. It opens readers lazily (only when a lookup is requested) and caches them for the lifetime of the process. This avoids reopening `.mmdb` files on every node lookup.

**Alternative considered**: Inline `geoip2` calls in `scanner.py` — rejected; hard to test and couples scanner to file paths.

### 2. MaxMind fills gaps, Shodan data is kept as primary

When Shodan provides a non-null value (e.g., `country_code`), it is preserved. MaxMind data is only written to fields that are `None` or empty. Exception: `latitude`/`longitude` always use MaxMind when available, because Shodan's coordinates are often null.

**Alternative considered**: Always prefer MaxMind — rejected; Shodan sometimes has more precise ISP/ASN names for Bitcoin-specific hosts.

### 3. Additive `subdivision` column via Alembic migration

A `subdivision` (String 100, nullable) column is added to `nodes`. This is purely additive and safe to apply against existing databases.

### 4. Retroactive enrichment as a separate CLI subcommand

`bitcoin-scanner db enrich-geo` iterates all nodes in the DB, calls `GeoIPService.lookup(ip)`, and writes missing fields. Uses the existing `NodeRepository` session. Runs in a single transaction per batch of 500.

**Alternative considered**: Auto-run enrichment on every app start — rejected; too slow for large DBs and surprising to operators.

### 5. `GET /api/v1/nodes/{id}/geo` endpoint

Returns the full geo record for a node: country, city, subdivision, lat/lon, ASN. Reuses the existing `require_api_key` dependency and `get_db` session factory.

### 6. Download helper script (not Python)

`scripts/download_geoip_dbs.sh` uses `curl` to fetch the three `.mmdb` files from MaxMind's download API (requires `MAXMIND_LICENSE_KEY` env var). Shell script keeps the Python package free of download logic. Users run it once after setup.

## Risks / Trade-offs

- **`.mmdb` file not present at startup**: `GeoIPService` logs a warning and returns `None` for all lookups — scan continues without geo enrichment. Fail-open is preferable to crashing.
- **GeoLite2 accuracy**: City-level accuracy is ~80% for many countries; coordinates are city centroid, not exact. This is sufficient for the scanner's threat intelligence use case.
- **License compliance**: GeoLite2 requires attribution in any public-facing output. The web dashboard and reports should note "This product includes GeoLite2 data created by MaxMind."
- **File staleness**: MaxMind releases updates weekly. `scripts/download_geoip_dbs.sh` should be re-run periodically (document in README as monthly refresh cadence).

## Migration Plan

1. Add `geoip2>=4.8.0` to `requirements.txt`
2. Create Alembic migration `003_add_subdivision.py` adding `subdivision` column to `nodes`
3. Implement `src/geoip.py` with `GeoIPService` and `GeoRecord` dataclass
4. Inject `GeoIPService` into scanner enrichment step (fill gaps after Shodan data)
5. Add `enrich-geo` subcommand to `src/db/cli.py`
6. Add `GET /api/v1/nodes/{id}/geo` to `src/web/routers/nodes.py`
7. Add `scripts/download_geoip_dbs.sh`
8. Add `GEOIP_DB_DIR` and `MAXMIND_LICENSE_KEY` to `.env.example`
9. Update README with setup instructions

**Rollback**: Delete `src/geoip.py`, remove the migration, remove the CLI subcommand and API endpoint. No other code is structurally changed.

## Open Questions

- Should `enrich-geo` overwrite existing non-null Shodan values, or strictly fill gaps? (Assumed: fill gaps only, matching the general MaxMind-as-supplement principle)
- Should the download script support GeoLite2 auto-update via cron? (Assumed: out of scope for now — document manual refresh)
