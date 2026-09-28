import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("./config", () => ({ serverConfig: { apiBaseUrl: "http://api", bffSharedSecret: "s" } }));

const dropped = () => Object.assign(new TypeError("fetch failed"), { cause: { code: "UND_ERR_SOCKET" } });

describe("callApi", () => {
  it("retries a GET once when the pooled connection was dropped", async () => {
    const fetchMock = vi.fn().mockRejectedValueOnce(dropped()).mockResolvedValueOnce(new Response("ok"));
    vi.stubGlobal("fetch", fetchMock);
    const { callApi } = await import("./api");
    expect(await (await callApi("/v1/public/case")).text()).toBe("ok");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("never retries a POST", async () => {
    const fetchMock = vi.fn().mockRejectedValue(dropped());
    vi.stubGlobal("fetch", fetchMock);
    const { callApi } = await import("./api");
    await expect(callApi("/v1/public/requests", { method: "POST", body: {} })).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
