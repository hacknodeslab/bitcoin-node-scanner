## ADDED Requirements

### Requirement: Nostr relay list endpoint

The API SHALL expose `GET /api/v1/nostr/relays` returning a paginated list of relays from the latest scan, filterable by `verdict`, `provider`, and `behind_cdn`, behind the existing API-key authentication.

#### Scenario: Paginated relay list

- **WHEN** an authenticated client requests `GET /api/v1/nostr/relays`
- **THEN** the response is a paginated list of relay items, each including `host`, `verdict`, `providers`, and `ips`

#### Scenario: Filter by provider

- **WHEN** the request includes `?provider=cloudflare`
- **THEN** only relays whose providers include `cloudflare` are returned

#### Scenario: Filter to relays behind a CDN

- **WHEN** the request includes `?behind_cdn=true`
- **THEN** relays with verdict `direct`, `dns_error`, or `skipped` are excluded

#### Scenario: Unauthenticated request rejected

- **WHEN** the request omits a valid API key
- **THEN** the API responds with `401 Unauthorized`

### Requirement: Nostr stats endpoint

The API SHALL expose `GET /api/v1/nostr/stats` returning aggregates for the latest scan: counts per verdict, `total`, `resolved`, `behind_any_cdn`, and the percentage of resolved relays behind any CDN.

#### Scenario: Aggregate stats returned

- **WHEN** an authenticated client requests `GET /api/v1/nostr/stats`
- **THEN** the response includes per-verdict counts, `total`, `resolved`, `behind_any_cdn`, and the behind-CDN percentage

#### Scenario: No scans yet

- **WHEN** no Nostr scan has been imported
- **THEN** the endpoint returns zeroed/empty aggregates rather than an error
