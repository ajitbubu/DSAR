import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const jar = new Map<string, { value: string }>();
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (n: string) => jar.get(n) }) }));
const getStaffSession = vi.fn();
vi.mock("@/lib/server/staff-session", () => ({ getStaffSession: () => getStaffSession() }));

const { POST } = await import("./route");

const ORIGIN = "http://localhost:3000";
const CASE = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";
const ALLOWED = ["v1", "cases", CASE, "approvals"];

function call(path: string[], headers: Record<string, string> = {}, body: unknown = { decision: "APPROVE" }) {
  const req = new Request(`${ORIGIN}/api/staff/${path.join("/")}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, "sec-fetch-site": "same-origin",
               "x-csrf-token": "csrf-token", ...headers },
    body: JSON.stringify(body),
  });
  return POST(req, { params: Promise.resolve({ path }) });
}

describe("POST /api/staff/[...path]", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    process.env.API_BASE_URL = "http://api.internal";
    jar.clear();
    jar.set("__Host-idp_csrf", { value: "csrf-token" });
    getStaffSession.mockResolvedValue({ accessToken: "staff-access-token" });
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it.each([
    [["v1", "audit", "events"], "a path that isn't an allowlisted mutation"],
    [["v1", "cases", CASE, "..", "..", "audit", "verify-all"], "a traversal attempt"],
    [["v1", "cases", "not-a-uuid", "approvals"], "a malformed case id"],
    [["v1", "test-support", "rate-limits", "reset"], "a test-only endpoint"],
  ])("refuses %j (%s) without asking for a session or calling the API", async (path) => {
    const res = await call(path as string[]);
    expect(res.status).toBe(404);
    expect(getStaffSession).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a missing or wrong CSRF token", async () => {
    expect((await call(ALLOWED, { "x-csrf-token": "" })).status).toBe(403);
    expect((await call(ALLOWED, { "x-csrf-token": "other-token" })).status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a cross-site request even with a valid token", async () => {
    expect((await call(ALLOWED, { origin: "https://evil.example" })).status).toBe(403);
    expect((await call(ALLOWED, { "sec-fetch-site": "cross-site" })).status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses without a staff session", async () => {
    getStaffSession.mockResolvedValue(null);
    expect((await call(ALLOWED)).status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards as the signed-in user and passes a well-formed idempotency key", async () => {
    fetchMock.mockResolvedValue(Response.json({ id: "a1" }, { status: 201 }));
    const res = await call(ALLOWED, { "idempotency-key": "k".repeat(24) });
    expect(res.status).toBe(201);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`http://api.internal/v1/cases/${CASE}/approvals`);
    expect(init.headers.Authorization).toBe("Bearer staff-access-token");
    expect(init.headers["Idempotency-Key"]).toBe("k".repeat(24));
    expect(JSON.parse(init.body)).toEqual({ decision: "APPROVE" });
  });

  it("drops a malformed idempotency key instead of forwarding it", async () => {
    fetchMock.mockImplementation(async () => Response.json({}, { status: 200 }));
    await call(ALLOWED, { "idempotency-key": "bad key; x-injected=1" });
    expect(fetchMock.mock.calls[0]![1].headers["Idempotency-Key"]).toBeUndefined();
    await call(ALLOWED, { "idempotency-key": "short" });  // under 16 characters
    expect(fetchMock.mock.calls[1]![1].headers["Idempotency-Key"]).toBeUndefined();
  });

  it("relays the API answer without its internal headers", async () => {
    fetchMock.mockResolvedValue(new Response("{}", {
      status: 429,
      headers: { "content-type": "application/problem+json", "retry-after": "7",
                 "set-cookie": "internal=1", server: "uvicorn" },
    }));
    const res = await call(ALLOWED);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("7");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.headers.get("server")).toBeNull();
  });

  it("refuses an oversized body", async () => {
    const res = await call(ALLOWED, {}, { notes: "x".repeat(70 * 1024) });
    expect(res.status).toBe(413);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
