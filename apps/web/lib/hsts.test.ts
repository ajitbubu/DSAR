import { describe, expect, it } from "vitest";
import { hstsHeader } from "./hsts";

describe("hstsHeader", () => {
  it("is sent over https", () => {
    expect(hstsHeader("https://privacy.example.com")).toBe("max-age=31536000; includeSubDomains");
  });
  it.each([undefined, "http://localhost:3000", ""])("is not sent for %s", (origin) => {
    expect(hstsHeader(origin)).toBeNull();
  });
});
