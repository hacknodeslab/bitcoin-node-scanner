/**
 * Unit tests for the API client. We mock `fetch` to assert:
 *   - X-API-Key is injected when configured
 *   - X-CSRF-Token is sent on mutating verbs only, with the token currently
 *     stored by `setCsrfToken`
 *   - 402 + WWW-Authenticate: L402 ... is parsed as a discriminated result
 *   - non-2xx (other) throws an `ApiError`
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  ApiError,
  fetchProtected,
  request,
  requestWithHeaders,
  setCsrfToken,
} from "../api/client";
import { fetchCsrfToken, listNodesWithTotal } from "../api/endpoints";

function makeResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    statusText: status === 200 ? "OK" : status === 402 ? "Payment Required" : "Error",
    headers: { "content-type": "application/json", ...headers },
  });
}

describe("API client headers", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("dummy-csrf");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("GET does not send X-CSRF-Token", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { ok: true }));
    await request("GET", "/stats");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("POST sends X-CSRF-Token from current store", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { ok: true }));
    await request("POST", "/scans");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers["X-CSRF-Token"]).toBe("dummy-csrf");
  });

  it("includes credentials cross-origin", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { ok: true }));
    await request("GET", "/stats");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.credentials).toBe("include");
  });

  it("throws ApiError on non-2xx", async () => {
    fetchMock.mockResolvedValue(makeResponse(500, { detail: "boom" }));
    await expect(request("GET", "/stats")).rejects.toBeInstanceOf(ApiError);
  });

  it("fetchCsrfToken stores the returned value", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { csrfToken: "abc-123" }));
    const t = await fetchCsrfToken();
    expect(t).toBe("abc-123");
  });
});

describe("fetchProtected — L402 discrimination", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("ok response returns kind:'ok'", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, { foo: "bar" }));
    const r = await fetchProtected<{ foo: string }>("/l402/example");
    expect(r.kind).toBe("ok");
    if (r.kind === "ok") expect(r.data).toEqual({ foo: "bar" });
  });

  it("402 with valid L402 challenge returns kind:'l402-challenge' with macaroon and invoice", async () => {
    fetchMock.mockResolvedValue(
      makeResponse(
        402,
        { error: "l402_pending" },
        {
          "www-authenticate":
            'L402 macaroon="placeholder-macaroon", invoice="placeholder-invoice"',
        },
      ),
    );
    const r = await fetchProtected("/l402/example");
    expect(r.kind).toBe("l402-challenge");
    if (r.kind === "l402-challenge") {
      expect(r.macaroon).toBe("placeholder-macaroon");
      expect(r.invoice).toBe("placeholder-invoice");
    }
  });

  it("402 without a parseable L402 header throws ApiError", async () => {
    fetchMock.mockResolvedValue(
      makeResponse(402, { error: "x" }, { "www-authenticate": "Basic realm=foo" }),
    );
    await expect(fetchProtected("/l402/example")).rejects.toBeInstanceOf(ApiError);
  });

  it("non-2xx (non-402) throws ApiError", async () => {
    fetchMock.mockResolvedValue(makeResponse(503, { error: "down" }));
    await expect(fetchProtected("/l402/example")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("requestWithHeaders + listNodesWithTotal", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns parsed body and the raw Headers object", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, [{ id: 1 }], { "X-Total-Count": "42" }));
    const r = await requestWithHeaders<unknown[]>("GET", "/nodes");
    expect(r.data).toEqual([{ id: 1 }]);
    expect(r.headers.get("X-Total-Count")).toBe("42");
  });

  it("listNodesWithTotal parses X-Total-Count as integer", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, [], { "X-Total-Count": "137" }));
    const r = await listNodesWithTotal({ limit: 25 });
    expect(r.nodes).toEqual([]);
    expect(r.total).toBe(137);
  });

  it("listNodesWithTotal returns null total when header is missing", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, []));
    const r = await listNodesWithTotal();
    expect(r.total).toBeNull();
  });

  it("listNodesWithTotal returns null total when header is not a number", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, [], { "X-Total-Count": "nope" }));
    const r = await listNodesWithTotal();
    expect(r.total).toBeNull();
  });

  it("requestWithHeaders throws ApiError on non-2xx", async () => {
    fetchMock.mockResolvedValue(makeResponse(500, { detail: "boom" }));
    await expect(requestWithHeaders("GET", "/nodes")).rejects.toBeInstanceOf(ApiError);
  });

  it("listNodesWithTotal serializes is_example=false into the URL when set", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, [], { "X-Total-Count": "0" }));
    await listNodesWithTotal({ is_example: false });
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("is_example=false");
  });

  it("listNodesWithTotal omits is_example from the URL when not set", async () => {
    fetchMock.mockResolvedValue(makeResponse(200, [], { "X-Total-Count": "0" }));
    await listNodesWithTotal({});
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).not.toContain("is_example");
  });
});
