import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const jar = new Map<string, { value: string }>();
const sets: { name: string; value: string; opts: Record<string, unknown> }[] = [];
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (n: string) => jar.get(n),
    set: (n: string, value: string, opts: Record<string, unknown>) => {
      sets.push({ name: n, value, opts });
      jar.set(n, { value });
    },
    delete: (n: string) => jar.delete(n),
  }),
}));

const ORIGIN = "http://localhost:3000";
const CHALLENGE = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";
const pending = (slug = "acme") =>
  Buffer.from(JSON.stringify({ challengeId: CHALLENGE, displayId: "DPR-2026-7K4Q9M",
                               destinationHint: "p•••@e•••.in", slug })).toString("base64url");

function post(path: string, headers: Record<string, string> = {}, body: unknown = {}) {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, "sec-fetch-site": "same-origin",
               "x-csrf-token": "csrf-token", ...headers },
    body: JSON.stringify(body),
  });
}

const fetchMock = vi.fn();
beforeEach(() => {
  process.env.BFF_SHARED_SECRET = "s".repeat(40);
  process.env.API_BASE_URL = "http://api.internal";
  jar.clear();
  sets.length = 0;
  jar.set("__Host-idp_csrf", { value: "csrf-token" });
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

const { GET } = await import("./route");
const get = (fmt: string) =>
  GET(new Request(`${ORIGIN}/api/public/report/${fmt}`), { params: Promise.resolve({ fmt }) });

describe("GET /api/public/report/[fmt]", () => {
  it("serves only json and html, and only with a tracking session", async () => {
    expect((await get("pdf")).status).toBe(404);
    expect((await get("../../v1/cases")).status).toBe(404);
    expect((await get("json")).status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes the report through with only safe headers", async () => {
    jar.set("__Host-idp_dp", { value: "dp-session-secret" });
    fetchMock.mockResolvedValue(new Response("<html>report</html>", {
      status: 200,
      headers: { "content-type": "text/html", "content-security-policy": "default-src 'none'",
                 "set-cookie": "internal=1" },
    }));
    const res = await get("html");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toBe("default-src 'none'");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("relays a used-up or expired report", async () => {
    jar.set("__Host-idp_dp", { value: "dp-session-secret" });
    fetchMock.mockResolvedValue(Response.json({ title: "Gone" }, { status: 410 }));
    expect((await get("json")).status).toBe(410);
  });
});
