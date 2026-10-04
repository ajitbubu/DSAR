import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const jar = new Map<string, { value: string }>();
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (n: string) => jar.get(n) }) }));
const getStaffSession = vi.fn();
vi.mock("@/lib/server/staff-session", () => ({ getStaffSession: () => getStaffSession() }));

const { POST } = await import("./route");

const ORIGIN = "http://localhost:3000";
const CASE = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";
const MULTIPART = "multipart/form-data; boundary=----x";

function upload(path: string[], headers: Record<string, string> = {}, body = "------x--") {
  const req = new Request(`${ORIGIN}/api/staff-upload/${path.join("/")}`, {
    method: "POST",
    headers: { "content-type": MULTIPART, origin: ORIGIN, "sec-fetch-site": "same-origin",
               "x-csrf-token": "csrf-token", ...headers },
    body,
  });
  return POST(req, { params: Promise.resolve({ path }) });
}

describe("POST /api/staff-upload/[...path]", () => {
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

  it("only accepts the evidence upload path", async () => {
    expect((await upload(["v1", "cases", CASE, "approvals"])).status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a non-multipart body, a missing token and a cross-site origin", async () => {
    const path = ["v1", "cases", CASE, "evidence"];
    expect((await upload(path, { "content-type": "application/json" })).status).toBe(403);
    expect((await upload(path, { "x-csrf-token": "" })).status).toBe(403);
    expect((await upload(path, { origin: "https://evil.example" })).status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a declared size over 10 MB before reading it", async () => {
    const res = await upload(["v1", "cases", CASE, "evidence"], { "content-length": String(11 * 1024 * 1024) });
    expect(res.status).toBe(413);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses without a staff session", async () => {
    getStaffSession.mockResolvedValue(null);
    expect((await upload(["v1", "cases", CASE, "evidence"])).status).toBe(401);
  });

  it("forwards the multipart body as the signed-in user", async () => {
    fetchMock.mockResolvedValue(Response.json({ id: "e1" }, { status: 201 }));
    const res = await upload(["v1", "cases", CASE, "evidence"]);
    expect(res.status).toBe(201);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`http://api.internal/v1/cases/${CASE}/evidence`);
    expect(init.headers).toEqual({ Authorization: "Bearer staff-access-token", "Content-Type": MULTIPART });
  });
});
