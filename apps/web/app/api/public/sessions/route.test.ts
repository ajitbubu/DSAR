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

describe("POST /api/public/sessions (returning sign-in)", () => {
  it("refuses a cross-site request without calling the API", async () => {
    expect((await POST(post("/api/public/sessions", { origin: "https://evil.example" }))).status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps the challenge id in an httpOnly cookie, not in the response", async () => {
    fetchMock.mockResolvedValue(Response.json({ challengeId: CHALLENGE, destinationHint: "p•••@e•••.in" }, { status: 202 }));
    const res = await POST(post("/api/public/sessions", {}, { intakeSlug: "acme", reference: "DPR-2026-7K4Q9M" }));
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body).toEqual({ destinationHint: "p•••@e•••.in" });
    expect(JSON.stringify(body)).not.toContain(CHALLENGE);
    const cookie = sets.find((c) => c.name === "__Host-idp_challenge")!;
    expect(cookie.opts).toMatchObject({ httpOnly: true, sameSite: "strict", maxAge: 1800 });
  });

  it("sets no cookie when the API refuses", async () => {
    fetchMock.mockResolvedValue(Response.json({}, { status: 429, headers: { "retry-after": "60" } }));
    const res = await POST(post("/api/public/sessions", {}, { intakeSlug: "acme", reference: "x" }));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(sets).toHaveLength(0);
  });
});
