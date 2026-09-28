import { describe, expect, it } from "vitest";
import { safeReturnTo } from "./safe-redirect";

describe("safeReturnTo", () => {
  it.each([
    ["/ops", "/ops"],
    ["/ops/cases/123/discovery", "/ops/cases/123/discovery"],
    ["/ops?status=UNDER_REVIEW", "/ops?status=UNDER_REVIEW"],
  ])("keeps %s", (raw, expected) => expect(safeReturnTo(raw)).toBe(expected));

  it.each([
    null, "", "https://evil.example/ops", "//evil.example/ops", "/\\evil.example",
    "/r/acme", "javascript:alert(1)", "/ops" + "x".repeat(600), "/ops/../api/auth/logout",
  ])("rejects %s", (raw) => {
    const out = safeReturnTo(raw as string | null);
    expect(out === "/ops" || out.startsWith("/ops")).toBe(true);
    expect(out).not.toContain("evil");
    expect(out).not.toContain("/api/");
  });
});
