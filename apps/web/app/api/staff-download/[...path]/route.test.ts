import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getStaffSession = vi.fn();
vi.mock("@/lib/server/staff-session", () => ({ getStaffSession: () => getStaffSession() }));

const { GET } = await import("./route");

const CASE = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";
const FILE = "0f9e7d1c-2b3a-4c5d-8e6f-7a8b9c0d1e2f";
const CONTENT = ["v1", "cases", CASE, "evidence", FILE, "content"];

const download = (path: string[]) =>
  GET(new Request("http://localhost:3000/api/staff-download/x"), { params: Promise.resolve({ path }) });

describe("GET /api/staff-download/[...path]", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    process.env.API_BASE_URL = "http://api.internal";
    getStaffSession.mockResolvedValue({ accessToken: "staff-access-token" });
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("only serves evidence file content", async () => {
    expect((await download(["v1", "cases", CASE, "evidence"])).status).toBe(404);
    expect((await download(["v1", "audit", "events"])).status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses without a staff session", async () => {
    getStaffSession.mockResolvedValue(null);
    expect((await download(CONTENT)).status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes only safe headers through and marks the file nosniff", async () => {
    fetchMock.mockResolvedValue(new Response("%PDF-1.7", {
      status: 200,
      headers: { "content-type": "application/pdf", "content-disposition": "attachment; filename=e.pdf",
                 "x-content-sha256": "ab".repeat(32), "set-cookie": "internal=1", server: "uvicorn" },
    }));
    const res = await download(CONTENT);
    expect(res.status).toBe(200);
    expect(fetchMock.mock.calls[0]![1].headers.Authorization).toBe("Bearer staff-access-token");
    expect(res.headers.get("content-type")).toBe("application/pdf");
    expect(res.headers.get("x-content-sha256")).toBe("ab".repeat(32));
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.headers.get("server")).toBeNull();
    expect(await res.text()).toBe("%PDF-1.7");
  });

  it.each([[403, 403], [404, 404], [500, 404]])(
    "maps an API %i to %i without relaying the API body", async (apiStatus, status) => {
      fetchMock.mockResolvedValue(new Response("internal stack trace", { status: apiStatus }));
      const res = await download(CONTENT);
      expect(res.status).toBe(status);
      expect(await res.text()).not.toContain("stack trace");
    },
  );
});
