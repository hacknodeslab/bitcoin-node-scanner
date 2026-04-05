## ADDED Requirements

### Requirement: Fetch CVE entries from NVD API v2
The system SHALL implement an HTTP client that queries the NVD REST API v2 endpoint `https://services.nvd.nist.gov/rest/json/cves/2.0` with `keywordSearch=bitcoin`, handles pagination via `startIndex` and `resultsPerPage`, and returns a complete list of CVE items.

#### Scenario: Successful paginated fetch
- **WHEN** the NVD API is reachable and returns results across multiple pages
- **THEN** the client SHALL iterate all pages and return the combined list of CVE items

#### Scenario: Fetch with API key
- **WHEN** `NVD_API_KEY` environment variable is set
- **THEN** the client SHALL include the `apiKey` query parameter on every request, allowing up to 50 requests per 30 seconds

#### Scenario: Fetch without API key (rate-limit-safe)
- **WHEN** `NVD_API_KEY` is not set
- **THEN** the client SHALL insert a minimum 0.6-second delay between paginated requests to stay within the 5 requests/30s public rate limit

### Requirement: Handle NVD API errors gracefully
The client SHALL raise a typed exception (`NVDAPIError`) on HTTP errors (4xx/5xx) and network timeouts, including the HTTP status code and response body in the exception message.

#### Scenario: HTTP 403 due to rate limit
- **WHEN** the NVD API responds with HTTP 403 (rate limit exceeded)
- **THEN** the client SHALL raise `NVDAPIError` with status code 403 and the response message

#### Scenario: Network timeout
- **WHEN** a request to NVD API times out after the configured timeout (default 30s)
- **THEN** the client SHALL raise `NVDAPIError` with a descriptive timeout message

### Requirement: Map NVD response to internal CVE model
The client SHALL parse each CVE item from the NVD response and return a list of `CVEEntry` dataclass instances with fields: `cve_id`, `published`, `last_modified`, `severity` (from CVSS v3 or v2), `cvss_score` (float or None), `description` (English text), `affected_versions` (list of CPE version strings).

#### Scenario: CVE with CVSS v3 score
- **WHEN** a CVE item contains a `cvssMetricV31` or `cvssMetricV30` entry
- **THEN** the mapped `CVEEntry` SHALL use the CVSS v3 `baseSeverity` and `baseScore`

#### Scenario: CVE without CVSS score
- **WHEN** a CVE item has no CVSS metrics
- **THEN** `severity` SHALL be `"UNKNOWN"` and `cvss_score` SHALL be `None`
