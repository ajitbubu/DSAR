import { describe, expect, it } from "vitest";
import { securityHeaders } from "./security-headers";

describe("securityHeaders", () => {
  const byKey = Object.fromEntries(securityHeaders.map((h) => [h.key, h.value]));

  it("never sends a Referer, so case URLs can't leak to third parties", () => {
    expect(byKey["Referrer-Policy"]).toBe("no-referrer");
  });

  it("blocks MIME sniffing and framing", () => {
    expect(byKey["X-Content-Type-Options"]).toBe("nosniff");
    expect(byKey["X-Frame-Options"]).toBe("DENY");
  });
});
