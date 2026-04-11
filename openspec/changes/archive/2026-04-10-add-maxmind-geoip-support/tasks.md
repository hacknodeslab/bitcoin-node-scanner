## 1. Dependencies & Configuration

- [x] 1.1 Add `geoip2>=4.8.0` to `requirements.txt`
- [x] 1.2 Add `GEOIP_DB_DIR` (default `./geoip_dbs/`) and `MAXMIND_LICENSE_KEY` to `.env.example`
- [x] 1.3 Add `geoip_dbs/` to `.gitignore` (binary `.mmdb` files must not be committed)

## 2. Database Migration

- [x] 2.1 Create Alembic migration `003_add_subdivision.py` adding a nullable `subdivision` column (String 100) to the `nodes` table
- [x] 2.2 Add `subdivision: Mapped[Optional[str]]` field to the `Node` SQLAlchemy model in `src/db/models.py`
- [x] 2.3 Update `NodeOut` Pydantic schema in `src/web/routers/nodes.py` to include the `subdivision` field

## 3. GeoIPService

- [x] 3.1 Create `src/geoip.py` with:
  - `GeoRecord` dataclass: `country_code`, `country_name`, `city`, `subdivision`, `latitude`, `longitude`, `asn`, `asn_name`
  - `GeoIPService(db_dir: str)` class with lazy-loaded readers for `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
  - `lookup(ip: str) -> Optional[GeoRecord]` method — returns `None` for private IPs, unregistered IPs, or missing databases
  - Warning log (not exception) when `.mmdb` files are absent
- [x] 3.2 Write unit tests for `GeoIPService` in `tests/test_geoip.py`:
  - Test `lookup` returns `None` for private IPs (`10.x`, `192.168.x`, `127.x`)
  - Test graceful degradation when db files are missing
  - Test `GeoRecord` fields are populated (mock `geoip2.database.Reader`)

## 4. Scanner Integration

- [x] 4.1 Update `scanner.py` node enrichment to instantiate `GeoIPService` (using `GEOIP_DB_DIR` env var) and call `lookup(ip)` after Shodan data is collected — write MaxMind fields only where Shodan left them null (always write `latitude`, `longitude`, `subdivision` as Shodan doesn't provide these)
- [x] 4.2 Update `src/db/scanner_integration.py` to pass `subdivision` through to the Node model when saving enriched node data

## 5. Download Helper Script

- [x] 5.1 Create `scripts/download_geoip_dbs.sh` that:
  - Reads `MAXMIND_LICENSE_KEY` from environment, exits with error if unset
  - Creates `GEOIP_DB_DIR` directory if it doesn't exist (default `./geoip_dbs/`)
  - Downloads and extracts `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, `GeoLite2-Country.mmdb` via MaxMind download API
  - Prints progress and final success/failure message
- [x] 5.2 Make the script executable: `chmod +x scripts/download_geoip_dbs.sh`

## 6. CLI Enrichment Command

- [x] 6.1 Add `enrich-geo` subcommand to `src/db/cli.py` that:
  - Instantiates `GeoIPService`; exits with actionable error if databases are missing
  - Queries all nodes in batches of 500
  - For each node, calls `lookup(ip)` and updates only null fields (always updates `latitude`, `longitude`, `subdivision`)
  - Commits each batch
  - Prints running progress (`node X/Y`) and final summary (updated / skipped / no match)

## 7. Web API Endpoint

- [x] 7.1 Add `GET /api/v1/nodes/{id}/geo` to `src/web/routers/nodes.py` returning a `NodeGeoOut` Pydantic model with all geo fields
- [x] 7.2 Write integration test in `tests/test_web_api.py` covering: found (200 with geo fields), not found (404), missing API key (401)

## 8. Documentation

- [x] 8.1 Add "MaxMind GeoIP Setup" section to `README.md` explaining: obtaining a license key, running the download script, setting `GEOIP_DB_DIR`, and running `enrich-geo`
- [x] 8.2 Add attribution note ("This product includes GeoLite2 data created by MaxMind, available from maxmind.com") to README and web dashboard footer
