import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const jar = new Map<string, { value: string }>();
const setCalls: { name: string; value: string; opts: Record<string, unknown> }[] = [];

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => jar.get(name),
    set: (name: string, value: string, opts: Record<string, unknown>) => {
      setCalls.push({ name, value, opts });
      jar.set(name, { value });
    },
    delete: (name: string) => jar.delete(name),
  }),
}));

const { POST } = await import("./route");

const ORIGIN = "http://localhost:3000";
const CHALLENGE = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";

function request(headers: Record<string, string>, body = { intakeSlug: "acme" }) {
  return new Request(`${ORIGIN}/api/public/requests`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN,
               "sec-fetch-site": "same-origin", ...headers },
    body: JSON.stringify(body),
  });
}

describe("POST /api/public/requests", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    process.env.BFF_SHARED_SECRET = "s".repeat(40);
    process.env.API_BASE_URL = "http://api.internal";
    jar.clear();
    setCalls.length = 0;
    jar.set("__Host-idp_csrf", { value: "csrf-token" });
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("rejects a request without a CSRF token and never calls the API", async () => {
    const res = await POST(request({}));
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a cross-origin request even with a valid token", async () => {
    const res = await POST(request({ "x-csrf-token": "csrf-token", origin: "https://evil.example" }));
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards with the service credential and keeps the challenge id out of the browser", async () => {
    fetchMock.mockResolvedValue(Response.json(
      { displayId: "DPR-2026-7K4Q9M", challengeId: CHALLENGE, destinationHint: "p•••@e•••.in",
        expiresAt: "2026-09-26T00:00:00Z" },
      { status: 202 },
    ));
    const res = await POST(request({ "x-csrf-token": "csrf-token", "x-forwarded-for": "198.51.100.9" }));

    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body).toEqual({ displayId: "DPR-2026-7K4Q9M", destinationHint: "p•••@e•••.in" });
    expect(JSON.stringify(body)).not.toContain(CHALLENGE);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("http://api.internal/v1/public/requests");
    expect(init.headers["X-Internal-Auth"]).toBe("s".repeat(40));
    expect(init.headers["X-Client-IP"]).toBe("198.51.100.9");

    const cookie = setCalls.find((c) => c.name === "__Host-idp_challenge")!;
    expect(cookie.opts).toMatchObject({ httpOnly: true, secure: true, sameSite: "strict", path: "/" });
  });

  it("relays API validation errors without setting a challenge cookie", async () => {
    fetchMock.mockResolvedValue(Response.json({ title: "Unprocessable Entity", status: 422 },
                                              { status: 422 }));
    const res = await POST(request({ "x-csrf-token": "csrf-token" }));
    expect(res.status).toBe(422);
    expect(setCalls).toHaveLength(0);
  });

  it("rejects oversized bodies before calling the API", async () => {
    const res = await POST(request({ "x-csrf-token": "csrf-token" },
                                   { intakeSlug: "x".repeat(70 * 1024) }));
    expect(res.status).toBe(413);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
