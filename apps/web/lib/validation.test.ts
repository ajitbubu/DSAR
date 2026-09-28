import { describe, expect, it } from "vitest";
import { type ErasureFormValues, toRequestPayload, validateErasureForm, validateSignIn } from "./validation";

const valid: ErasureFormValues = {
  right: "ERASURE",
  fullName: "Priya Sharma",
  channel: "EMAIL",
  contact: "priya@example.in",
  customerId: "",
  details: "",
  residencyClaim: "IN",
  consent: true,
};

describe("validateErasureForm", () => {
  it("accepts a complete form", () => {
    expect(validateErasureForm(valid)).toEqual({});
  });

  it("requires name, contact and consent", () => {
    const e = validateErasureForm({ ...valid, fullName: "  ", contact: "", consent: false });
    expect(Object.keys(e).sort()).toEqual(["consent", "contact", "fullName"]);
  });

  it("enforces the same length limits as the API", () => {
    expect(validateErasureForm({ ...valid, fullName: "x".repeat(201) }).fullName).toBeDefined();
    expect(validateErasureForm({ ...valid, fullName: "x".repeat(200) }).fullName).toBeUndefined();
    expect(validateErasureForm({ ...valid, details: "d".repeat(2001) }).details).toBeDefined();
  });

  it("rejects control characters in free text", () => {
    expect(validateErasureForm({ ...valid, fullName: "Priya\u0000Sharma" }).fullName).toBeDefined();
    expect(validateErasureForm({ ...valid, fullName: "Priya​Sharma" }).fullName).toBeDefined();
    expect(validateErasureForm({ ...valid, details: "line one\nline two" }).details).toBeUndefined();
  });

  it.each(["not-an-email", "a@b", "a b@example.in"])("rejects email %s", (contact) => {
    expect(validateErasureForm({ ...valid, contact }).contact).toBeDefined();
  });

  it.each([
    ["+919876543210", undefined],
    ["9876543210", "error"],
    ["+91 98765 43210", "error"],
    ["+0123456789", "error"],
  ])("validates SMS number %s", (contact, expected) => {
    const e = validateErasureForm({ ...valid, channel: "SMS", contact });
    expect(e.contact === undefined ? undefined : "error").toBe(expected);
  });

  it("restricts customer IDs to the API's character set", () => {
    expect(validateErasureForm({ ...valid, customerId: "CUST-1001" }).customerId).toBeUndefined();
    expect(validateErasureForm({ ...valid, customerId: "CUST 1001" }).customerId).toBeDefined();
  });
});

describe("toRequestPayload", () => {
  it("omits blank optional fields and always requests erasure", () => {
    const p = toRequestPayload("acme", { ...valid, fullName: " Priya Sharma " });
    expect(p).toEqual({
      intakeSlug: "acme",
      rights: ["ERASURE"],
      fullName: "Priya Sharma",
      contact: { channel: "EMAIL", value: "priya@example.in" },
      additionalIdentifiers: [],
      residencyClaim: "IN",
      consentToProcess: true,
    });
  });

  it("includes a customer ID when given", () => {
    const p = toRequestPayload("acme", { ...valid, customerId: "CUST-1" });
    expect(p.additionalIdentifiers).toEqual([{ type: "CUSTOMER_ID", value: "CUST-1" }]);
  });
});

describe("right choice", () => {
  it("sends the chosen right", () => {
    expect(toRequestPayload("acme", { ...valid, right: "ACCESS" }).rights).toEqual(["ACCESS"]);
  });
});

describe("validateSignIn", () => {
  it("accepts a reference in any case and a matching contact", () => {
    expect(validateSignIn("dpr-2026-ab12cd", "EMAIL", "a@example.in")).toBeNull();
    expect(validateSignIn("DPR-2026-AB12CD", "SMS", "+919876543210")).toBeNull();
  });
  it("rejects malformed references and contacts", () => {
    expect(validateSignIn("DPR-26-AB", "EMAIL", "a@example.in")).toMatch(/reference/);
    expect(validateSignIn("DPR-2026-AB12CD<", "EMAIL", "a@example.in")).toMatch(/reference/);
    expect(validateSignIn("DPR-2026-AB12CD", "SMS", "98765")).toMatch(/mobile/);
  });
});
