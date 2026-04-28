/**
 * Typed fetch wrapper for the FastAPI backend.
 *
 * Responsibilities:
 *   1. Inject `X-API-Key` from the runtime config.
 *   2. Read the `csrftoken` cookie at request time and send it back as the
 *      `X-CSRF-Token` header on mutating verbs (per the double-submit
 *      pattern in `src/web/auth.py`). Cookie is HttpOnly=true → unreadable
 *      from JS; the token comes from the JSON body of `/csrf-token` instead.
 *      We hold it in module memory after the first fetch.
 *   3. Always send `credentials: "include"` so the browser attaches the
 *      `csrftoken` cookie cross-origin.
 *   4. Surface 402 + `WWW-Authenticate: L402 ...` as a discriminated result
 *      via `fetchProtected`, so callers can branch without throwing.
 */
import { API_BASE_URL, API_KEY } from "./config";
import type { ProtectedResult } from "./types";

let _csrfToken: string | null = null;

export function setCsrfToken(token: string) {
  _csrfToken = token;
}

export function getCsrfToken(): string | null {
  return _csrfToken;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public body: unknown,
  ) {
    super(`API ${status} ${statusText}`);
    this.name = "ApiError";
  }
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  headers?: Record<string, string>;
  /** Skip throwing on 402; let the caller see the raw Response. */
  allowL402?: boolean;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const target = path.startsWith("http") ? path : `${API_BASE_URL}${path}`;
  // API_BASE_URL may be absolute ("http://localhost:8000/api/v1") in dev or
  // relative ("/api/v1") in same-origin prod deploys. The URL constructor
  // requires a base when the first arg is relative.
  const base =
    typeof window !== "undefined" ? window.location.origin : "http://localhost";
  const url = new URL(target, base);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null) continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

async function rawRequest(
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...opts.headers,
  };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (MUTATING.has(method) && _csrfToken) {
    headers["X-CSRF-Token"] = _csrfToken;
  }

  return fetch(buildUrl(path, opts.query), {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    credentials: "include",
  });
}

/**
 * Send a request and parse the JSON body. Throws `ApiError` on non-2xx.
 * Treats 402 as an error — use `fetchProtected` for L402-aware flows.
 */
export async function request<T>(
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<T> {
  const r = await rawRequest(method, path, opts);
  if (!r.ok) {
    const body = await r
      .json()
      .catch(() => null as unknown);
    throw new ApiError(r.status, r.statusText, body);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

/**
 * L402-aware fetch. Returns a discriminated result so callers can branch on
 * `ok` vs `l402-challenge` without try/catch. Other non-2xx still throw.
 */
const L402_HEADER_RE = /^L402\s+macaroon="([^"]+)",\s*invoice="([^"]+)"/;

export async function fetchProtected<T>(
  path: string,
  opts: RequestOptions = {},
): Promise<ProtectedResult<T>> {
  const r = await rawRequest("GET", path, { ...opts, allowL402: true });

  if (r.status === 402) {
    const wwwAuth = r.headers.get("www-authenticate") ?? "";
    const m = L402_HEADER_RE.exec(wwwAuth);
    if (m) {
      return { kind: "l402-challenge", macaroon: m[1], invoice: m[2] };
    }
    throw new ApiError(402, r.statusText, await r.json().catch(() => null));
  }

  if (!r.ok) {
    throw new ApiError(r.status, r.statusText, await r.json().catch(() => null));
  }

  return { kind: "ok", data: (await r.json()) as T };
}
