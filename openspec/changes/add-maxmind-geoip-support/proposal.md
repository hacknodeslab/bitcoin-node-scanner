## Why

The scanner currently relies exclusively on Shodan's embedded location metadata for geolocation (`location.country_name`, `location.country_code`, `location.city`, `isp`, `asn`). This data is:

- **Incomplete**: Shodan omits city and coordinates for many nodes; `latitude`/`longitude` fields in the DB are often null.
- **Inaccurate**: Shodan's geo data can be outdated or coarse (country-level only).
- **Shodan-coupled**: Nodes added through other means (manual IP input, future sources) have no geo data at all.

MaxMind's GeoLite2 databases (free, licensed under CC BY-SA 4.0) provide high-accuracy, offline IP geolocation — including city, subdivision, coordinates, and ASN — without additional API calls or credits.

## What Changes

- Add a `GeoIPService` class backed by MaxMind GeoLite2-Country, GeoLite2-City, and GeoLite2-ASN `.mmdb` database files.
- Integrate the service into the scan pipeline: enrich each discovered node with MaxMind data, filling in gaps left by Shodan (coordinates, city, subdivision/region, precise ASN name).
- Add a CLI command `bitcoin-scanner db enrich-geo` to retroactively re-enrich all existing nodes in the database.
- Expose a `GET /api/v1/nodes/{id}/geo` endpoint in the web API returning full geo detail.
- Add a download helper script (`scripts/download_geoip_dbs.sh`) for obtaining the GeoLite2 `.mmdb` files.

## Capabilities

### New Capabilities

- `geoip-lookup`: Offline IP geolocation using local MaxMind GeoLite2 `.mmdb` files, returning country, city, subdivision, coordinates, and ASN.
- `geoip-enrichment`: Batch command to retroactively enrich all nodes in the database with MaxMind geo data.

### Modified Capabilities

<!-- No existing spec-level capabilities are being changed. Geo fields (latitude, longitude, city) already exist in the Node model and will simply be populated more reliably. -->

## Impact

- **New dependency**: `geoip2>=4.8.0` (MaxMind Python client for reading `.mmdb` files).
- **New env variables**: `GEOIP_DB_DIR` (path to directory containing `.mmdb` files, defaults to `./geoip_dbs/`).
- **DB schema**: No migration needed — `latitude`, `longitude`, `city`, `asn`, `asn_name` columns already exist. A new `subdivision` column (region/state) would be additive and beneficial.
- **Scan pipeline**: `GeoIPService` wraps `geoip2.database.Reader` and is injected into the scanner enrichment step — Shodan data is kept as primary source; MaxMind fills gaps.
- **Privacy/licensing**: GeoLite2 requires a free MaxMind account and license key for download. Files are stored locally; no network calls at runtime.
- **No breaking changes** to existing CLI, database schema (beyond additive column), or web API.
