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

describe("POST /api/public/resend", () => {
  it("needs CSRF and a pending challenge", async () => {
    expect((await POST(post("/api/public/resend", { "x-csrf-token": "" }))).status).toBe(403);
    expect((await POST(post("/api/public/resend"))).status).toBe(410);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("resends for the challenge in the cookie only", async () => {
    jar.set("__Host-idp_challenge", { value: pending() });
    fetchMock.mockResolvedValue(new Response(null, { status: 202 }));
    expect((await POST(post("/api/public/resend", {}, { challengeId: "someone-elses" }))).status).toBe(202);
    expect(fetchMock.mock.calls[0]![0]).toBe(`http://api.internal/v1/public/verifications/${CHALLENGE}/resend`);
  });
});
