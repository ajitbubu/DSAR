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

const { POST } = await import("./route");

describe("POST /api/public/verify", () => {
  it("refuses without CSRF, and without a pending challenge never calls the API", async () => {
    expect((await POST(post("/api/public/verify", { "x-csrf-token": "" }, { code: "123456" }))).status).toBe(403);
    expect((await POST(post("/api/public/verify", {}, { code: "123456" }))).status).toBe(410);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ignores a tampered challenge cookie", async () => {
    jar.set("__Host-idp_challenge", { value: Buffer.from('{"challengeId":"../../admin"}').toString("base64url") });
    expect((await POST(post("/api/public/verify", {}, { code: "123456" }))).status).toBe(410);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("on success stores the session in an httpOnly cookie, drops the challenge, and keeps the token out of the body", async () => {
    jar.set("__Host-idp_challenge", { value: pending() });
    fetchMock.mockResolvedValue(Response.json({ sessionToken: "dp-session-secret" }, { status: 200 }));
    const res = await POST(post("/api/public/verify", { "x-forwarded-for": "198.51.100.9" }, { code: "123456" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, slug: "acme" });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`http://api.internal/v1/public/verifications/${CHALLENGE}/confirm`);
    expect(init.headers["X-Internal-Auth"]).toBe("s".repeat(40));
    const cookie = sets.find((c) => c.name === "__Host-idp_dp")!;
    expect(cookie.value).toBe("dp-session-secret");
    expect(cookie.opts).toMatchObject({ httpOnly: true, secure: true, sameSite: "strict", path: "/" });
    expect(jar.has("__Host-idp_challenge")).toBe(false);
  });

  it("relays a wrong code without setting a session", async () => {
    jar.set("__Host-idp_challenge", { value: pending() });
    fetchMock.mockResolvedValue(Response.json({ title: "Unprocessable" }, { status: 422 }));
    expect((await POST(post("/api/public/verify", {}, { code: "000000" }))).status).toBe(422);
    expect(sets.find((c) => c.name === "__Host-idp_dp")).toBeUndefined();
    expect(jar.has("__Host-idp_challenge")).toBe(true);
  });
});
