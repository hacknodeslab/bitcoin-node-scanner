/**
 * API client configuration. Reads from public env vars at build time.
 *
 * - NEXT_PUBLIC_API_BASE_URL — base URL of the FastAPI backend, including
 *   the `/api/v1` prefix. May be absolute (dev: "http://localhost:8000/api/v1")
 *   or relative (prod same-origin: "/api/v1"). Default: dev absolute URL.
 * - NEXT_PUBLIC_WEB_API_KEY — shared API key sent as `X-API-Key`. The
 *   backend's WEB_API_KEY env var must match. NOTE: any NEXT_PUBLIC_*
 *   value is shipped to the browser. This matches the existing single-key
 *   architecture; a per-user auth model is out of scope for this change.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export const API_KEY = process.env.NEXT_PUBLIC_WEB_API_KEY ?? "";
