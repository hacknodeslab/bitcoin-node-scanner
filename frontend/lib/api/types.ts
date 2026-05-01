/**
 * TypeScript shapes matching the FastAPI response models in `src/web/routers/`.
 * Keep these in sync with the Pydantic models. A future change can autogenerate
 * them from `/openapi.json`; for now, hand-maintained.
 */

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface CVESummary {
  cve_id: string;
  severity: string;
  cvss_score: number | null;
}

export interface CVELink {
  cve_id: string;
  severity: string;
  cvss_score: number | null;
  description: string | null;
  detected_at: string | null;
  detected_version: string | null;
  resolved_at: string | null;
}

export interface NodeOut {
  id: number;
  ip: string;
  port: number;
  version: string | null;
  user_agent: string | null;
  protocol_version: number | null;
  services: string | null;
  risk_level: RiskLevel | null;
  is_vulnerable: boolean;
  has_exposed_rpc: boolean;
  is_dev_version: boolean;
  is_example: boolean;
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  subdivision: string | null;
  asn: string | null;
  asn_name: string | null;
  geo_country_code: string | null;
  geo_country_name: string | null;
  first_seen: string | null;
  last_seen: string | null;
  hostname: string | null;
  os_info: string | null;
  isp: string | null;
  org: string | null;
  open_ports: unknown[] | null;
  vulns: string[] | null;
  tags: string[] | null;
  cpe: string[] | null;
  cve_count: number;
  top_cve: CVESummary | null;
}

export interface NodeDetailOut extends NodeOut {
  cves: CVELink[];
}

export interface NodeGeoOut {
  id: number;
  ip: string;
  country_code: string | null;
  country_name: string | null;
  geo_country_code: string | null;
  geo_country_name: string | null;
  city: string | null;
  subdivision: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  asn_name: string | null;
}

export interface StatsOut {
  total_nodes: number;
  by_risk_level: Partial<Record<RiskLevel, number>>;
  by_country: Record<string, number>;
  vulnerable_nodes_count: number;
  exposed_count: number;
  stale_count: number;
  tor_count: number;
  ok_count: number;
  stale_threshold_days: number;
  last_scan_at: string | null;
  commit: string | null;
}

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export interface ScanJobOut {
  job_id: string;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  result_summary: Record<string, unknown> | null;
}

export interface CVEEntryOut {
  cve_id: string;
  published: string | null;
  last_modified: string | null;
  severity: string;
  cvss_score: number | null;
  description: string | null;
  affected_versions: string[] | null;
  fetched_at: string;
}

export interface VulnerabilitiesOut {
  total: number;
  items: CVEEntryOut[];
}

export interface CsrfTokenOut {
  csrfToken: string;
}

export interface NodeListParams {
  risk_level?: RiskLevel;
  country?: string;
  exposed?: boolean;
  tor?: boolean;
  is_example?: boolean;
  sort_by?: string;
  sort_dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

/**
 * Discriminated result of `fetchProtected`. Callers branch on `kind`:
 *   - `ok`: 2xx response, `data` is the parsed JSON body
 *   - `l402-challenge`: 402 with `WWW-Authenticate: L402 macaroon=..., invoice=...`
 */
export type ProtectedResult<T> =
  | { kind: "ok"; data: T }
  | { kind: "l402-challenge"; macaroon: string; invoice: string };
