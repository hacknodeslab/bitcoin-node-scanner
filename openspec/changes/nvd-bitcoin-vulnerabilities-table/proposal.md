## Why

The scanner collects data about Bitcoin nodes but lacks visibility into known CVEs and security vulnerabilities affecting Bitcoin software. Integrating the NVD (National Vulnerability Database) API from nvd.nist.gov allows operators to cross-reference node software versions against published vulnerabilities, enabling proactive security posture assessment.

## What Changes

- New endpoint to fetch and display Bitcoin-related CVE data from the NVD API
- Vulnerability table rendered in the web dashboard showing CVE ID, severity, CVSS score, description, and affected versions
- Background job or on-demand fetch to query NVD for CPE `cpe:2.3:a:bitcoin:bitcoin` and related entries
- Results cached in the database to avoid excessive API calls and support historical comparison

## Capabilities

### New Capabilities

- `nvd-api-client`: Fetches vulnerability data from the NVD REST API v2 (nvd.nist.gov/developers/vulnerabilities), filtering by keyword/CPE related to Bitcoin. Handles pagination, rate limiting, and API key authentication.
- `bitcoin-vulnerabilities-table`: Displays fetched CVE data as a sortable/filterable table in the web dashboard and exposes it via a REST endpoint. Includes CVE ID, severity, CVSS score, published date, description, and affected version ranges.

### Modified Capabilities

- `web-dashboard`: New vulnerabilities section/tab added to the existing dashboard UI.
- `web-api`: New `/vulnerabilities` endpoint returning paginated CVE data.

## Impact

- New dependency: HTTP client calls to `https://services.nvd.nist.gov/rest/json/cves/2.0`
- New database table: `cve_entries` to cache fetched vulnerabilities
- Existing web dashboard (`web/`) receives a new page/tab
- Optional: NVD API key configurable via environment variable for higher rate limits
