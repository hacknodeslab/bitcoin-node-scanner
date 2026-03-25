## ADDED Requirements

### Requirement: GeoIPService initializes from local .mmdb files
The system SHALL provide a `GeoIPService` class that opens MaxMind GeoLite2 `.mmdb` files from a configurable directory (`GEOIP_DB_DIR`, default `./geoip_dbs/`).

#### Scenario: Service initializes with all three databases present
- **WHEN** `GeoIPService(db_dir)` is instantiated and all three files (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, `GeoLite2-Country.mmdb`) exist in `db_dir`
- **THEN** the service SHALL be ready to perform lookups without error

#### Scenario: Service degrades gracefully when .mmdb files are missing
- **WHEN** `GeoIPService(db_dir)` is instantiated and one or more `.mmdb` files are absent
- **THEN** the service SHALL log a warning and return `None` for all lookups (fail-open, no exception raised)

### Requirement: IP lookup returns a GeoRecord dataclass
The system SHALL expose a `GeoIPService.lookup(ip: str) -> Optional[GeoRecord]` method returning structured geo data.

#### Scenario: Lookup for a known public IP returns full record
- **WHEN** `lookup("8.8.8.8")` is called with all databases present
- **THEN** the result SHALL be a `GeoRecord` with non-null `country_code`, `country_name`, `asn`, and `asn_name`; `city`, `subdivision`, `latitude`, `longitude` may be null for some IPs

#### Scenario: Lookup for a private/reserved IP returns None
- **WHEN** `lookup("192.168.1.1")` or `lookup("10.0.0.1")` is called
- **THEN** the result SHALL be `None` (private addresses are not in the GeoIP database)

#### Scenario: Lookup for an unknown/unregistered IP returns None
- **WHEN** `lookup` is called for an IP not present in the database
- **THEN** the result SHALL be `None` (no exception raised)

### Requirement: GeoIPService integrates into the scan pipeline
The system SHALL call `GeoIPService.lookup(ip)` during node enrichment and use the result to fill null geo fields.

#### Scenario: MaxMind fills missing latitude/longitude
- **WHEN** a node is enriched and Shodan provides no coordinates but MaxMind returns a valid `GeoRecord` with `latitude` and `longitude`
- **THEN** the node's `latitude` and `longitude` SHALL be set from the `GeoRecord`

#### Scenario: MaxMind does not overwrite existing Shodan values
- **WHEN** a node already has a non-null `country_code` from Shodan and MaxMind also returns a `country_code`
- **THEN** the existing Shodan `country_code` SHALL be preserved unchanged

#### Scenario: MaxMind sets subdivision field
- **WHEN** MaxMind returns a non-null subdivision (region/state) for a node
- **THEN** the node's `subdivision` field SHALL be set regardless of prior value (Shodan does not provide this field)

### Requirement: Download helper script
The system SHALL provide `scripts/download_geoip_dbs.sh` that downloads the three GeoLite2 `.mmdb` files using a MaxMind license key.

#### Scenario: Script downloads databases with valid license key
- **WHEN** the script is run with `MAXMIND_LICENSE_KEY` set in environment
- **THEN** it SHALL download `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`, and `GeoLite2-Country.mmdb` into `GEOIP_DB_DIR` (default `./geoip_dbs/`)

#### Scenario: Script exits with error when license key is missing
- **WHEN** the script is run without `MAXMIND_LICENSE_KEY` set
- **THEN** it SHALL print an error message and exit with a non-zero status code
