/**
 * Typed wrappers for `/api/v1/*` endpoints. The wrappers are thin — they
 * forward to `request<T>` with a fixed path and pass query params through.
 */
import { request, setCsrfToken, fetchProtected } from "./client";
import type {
  CsrfTokenOut,
  NodeGeoOut,
  NodeListParams,
  NodeOut,
  ProtectedResult,
  ScanJobOut,
  StatsOut,
  VulnerabilitiesOut,
} from "./types";

export async function fetchCsrfToken(): Promise<string> {
  const r = await request<CsrfTokenOut>("GET", "/csrf-token");
  setCsrfToken(r.csrfToken);
  return r.csrfToken;
}

export function getStats(): Promise<StatsOut> {
  return request<StatsOut>("GET", "/stats");
}

export function listNodes(params: NodeListParams = {}): Promise<NodeOut[]> {
  return request<NodeOut[]>("GET", "/nodes", { query: { ...params } });
}

export function listCountries(): Promise<string[]> {
  return request<string[]>("GET", "/nodes/countries");
}

export function getNodeGeo(nodeId: number): Promise<NodeGeoOut> {
  return request<NodeGeoOut>("GET", `/nodes/${nodeId}/geo`);
}

/**
 * V0 node-by-IP resolution: list and filter. The REST surface lacks
 * `GET /nodes/by-ip/{ip}` today (tracked as parity debt in `design.md` D10).
 * For typical operator queries the returned list is small, so this is good
 * enough for v0; M5 will use this where the drawer or palette opens by IP.
 */
export async function getNodeByIp(ip: string): Promise<NodeOut | null> {
  // The API doesn't filter by IP, so we paginate and scan.
  const matches = await listNodes({ limit: 1000 });
  return matches.find((n) => n.ip === ip) ?? null;
}

export function triggerScan(): Promise<ScanJobOut> {
  return request<ScanJobOut>("POST", "/scans");
}

export function getScanJob(jobId: string): Promise<ScanJobOut> {
  return request<ScanJobOut>("GET", `/scans/${jobId}`);
}

export function getVulnerabilities(): Promise<VulnerabilitiesOut> {
  return request<VulnerabilitiesOut>("GET", "/vulnerabilities");
}

/**
 * L402-aware example endpoint hit. Drawer's L402 button binds to this in v0;
 * subsequent changes will introduce real premium content endpoints that
 * surface the same discriminated `ProtectedResult`.
 */
export function fetchL402Example(): Promise<ProtectedResult<unknown>> {
  return fetchProtected<unknown>("/l402/example");
}
