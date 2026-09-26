import { describe, expect, it } from "vitest";
import { buildCsp } from "./csp";

describe("buildCsp", () => {
  const prod = buildCsp("abc123", { dev: false, https: true });

  it("uses a nonce and never allows inline or eval in production", () => {
    expect(prod).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(prod).not.toContain("unsafe-inline");
    expect(prod).not.toContain("unsafe-eval");
  });

  it("blocks framing, plugins and base-tag hijacking", () => {
    expect(prod).toContain("frame-ancestors 'none'");
    expect(prod).toContain("object-src 'none'");
    expect(prod).toContain("base-uri 'none'");
  });

  it("only upgrades insecure requests when served over https", () => {
    expect(prod).toContain("upgrade-insecure-requests");
    expect(buildCsp("n", { dev: false, https: false })).not.toContain("upgrade-insecure-requests");
  });
});
