import { describe, expect, it } from "vitest";
import { parseRecipients } from "./RegisterForm";

describe("parseRecipients", () => {
  it("parses name and kind, defaulting to processor", () => {
    expect(parseRecipients("Acme Mail Ltd | fiduciary\n\n  Pay Co  ")).toEqual([
      { name: "Acme Mail Ltd", kind: "FIDUCIARY" },
      { name: "Pay Co", kind: "PROCESSOR" },
    ]);
  });
  it("refuses unknown kinds and empty names", () => {
    expect(parseRecipients("Acme | FRIEND")).toBeNull();
    expect(parseRecipients(" | PROCESSOR")).toBeNull();
  });
  it("allows no recipients", () => expect(parseRecipients("  \n")).toEqual([]));
});
