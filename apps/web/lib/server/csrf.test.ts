import { describe, expect, it } from "vitest";
import { type CsrfInput, checkCsrf } from "./csrf";

const ok: CsrfInput = {
  method: "POST",
  origin: "http://localhost:3000",
  secFetchSite: "same-origin",
  contentType: "application/json",
  headerToken: "t0k3n",
  cookieToken: "t0k3n",
  expectedOrigin: "http://localhost:3000",
};

describe("checkCsrf", () => {
  it("allows a same-origin JSON request with matching tokens", () => {
    expect(checkCsrf(ok)).toBeNull();
  });

  it("does not gate safe methods", () => {
    expect(checkCsrf({ ...ok, method: "GET", headerToken: null, origin: null })).toBeNull();
  });

  it.each([
    ["missing origin", { origin: null }, "origin"],
    ["foreign origin", { origin: "https://evil.example" }, "origin"],
    ["lookalike origin", { origin: "http://localhost:3000.evil.example" }, "origin"],
    ["cross-site fetch", { secFetchSite: "cross-site" }, "fetch-site"],
    ["same-site (sibling subdomain)", { secFetchSite: "same-site" }, "fetch-site"],
    ["form post", { contentType: "application/x-www-form-urlencoded" }, "content-type"],
    ["text/plain", { contentType: "text/plain" }, "content-type"],
    ["no header token", { headerToken: null }, "token-missing"],
    ["no cookie token", { cookieToken: undefined }, "token-missing"],
    ["token mismatch", { headerToken: "other" }, "token-mismatch"],
    ["token length mismatch", { headerToken: "t0k3n-longer" }, "token-mismatch"],
  ] as const)("rejects %s", (_label, patch, reason) => {
    expect(checkCsrf({ ...ok, ...patch })).toBe(reason);
  });
});
