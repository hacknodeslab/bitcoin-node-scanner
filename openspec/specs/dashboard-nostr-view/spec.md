# dashboard-nostr-view Specification

## Purpose

Gives the dashboard a dedicated `/nostr` panel that surfaces the Nostr relay CDN-recon results: how centralized the relay network is, a per-provider breakdown, and a browsable table of relays with their verdicts. It is reachable from the persistent dashboard navigation and reuses the existing design-system tokens, theming, `Pill` component, and the table/pagination/filtering patterns from the node table.

## Requirements

### Requirement: Nostr panel route

The dashboard SHALL expose a `/nostr` route rendering the relay-behind-CDN recon panel, reachable from a persistent `nostr` entry in the top navigation.

#### Scenario: Navigate to the panel

- **WHEN** the user clicks the `nostr` nav link
- **THEN** the dashboard renders the `/nostr` page with the active nav item highlighted

#### Scenario: Empty state

- **WHEN** no Nostr scan has been imported yet
- **THEN** the page shows an empty state explaining that a scan must be imported, rather than an error

### Requirement: Centralization summary cards

The panel SHALL display summary statistics for the latest scan: total/resolved host counts, the percentage of resolved relays behind any tracked CDN, and a per-provider breakdown.

#### Scenario: Headline percentage shown

- **WHEN** the latest scan has resolved relays
- **THEN** the panel shows the percentage behind any CDN computed as `behind_any_cdn / resolved`

#### Scenario: Per-provider breakdown shown

- **WHEN** the latest scan contains relays across providers
- **THEN** the panel shows a count per provider (e.g. Cloudflare, CloudFront, Fastly)

### Requirement: Relay table with verdict pills, sorting, and pagination

The panel SHALL render a paginated, sortable table of relays showing host, verdict (as a `Pill`), providers, and resolved IPs, reusing the design-system tokens and the table/pagination patterns from the node table.

#### Scenario: Verdict rendered as a pill

- **WHEN** a relay row is displayed
- **THEN** its verdict is rendered as a `Pill` styled with design-system tokens, in both dark and light theme

#### Scenario: Sort and paginate

- **WHEN** the user sorts by a column or moves to another page
- **THEN** the table updates accordingly using the shared table/pagination behavior

### Requirement: Filter relays by verdict and provider

The panel SHALL let the user filter the relay table by verdict and by provider, and surface a "behind CDN" filter that excludes `direct`/`dns_error`/`skipped`.

#### Scenario: Filter to a single provider

- **WHEN** the user filters by `cloudflare`
- **THEN** the table shows only relays whose providers include Cloudflare

#### Scenario: Behind-CDN filter

- **WHEN** the user enables the "behind CDN" filter
- **THEN** the table excludes relays with verdict `direct`, `dns_error`, or `skipped`
