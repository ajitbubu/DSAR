import { describe, expect, it } from "vitest";
import { isAllowedStaffMutation } from "./staff-actions";

const ID = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";

describe("isAllowedStaffMutation", () => {
  it.each([
    `/v1/cases/${ID}/transitions`,
    `/v1/cases/${ID}/matches/${ID}/retention-decisions`,
    "/v1/legal-holds",
    `/v1/legal-holds/${ID}/release`,
    `/v1/cases/${ID}/approvals`,
  ])("allows %s", (p) => expect(isAllowedStaffMutation(p)).toBe(true));

  it.each([
    "/v1/admin/users",
    `/v1/cases/${ID}/transitions/../../admin`,
    `/v1/cases/${ID.toUpperCase()}/transitions`,
    "/v1/legal-holds/../me",
    `/v1/cases/${ID}/transitions?x=1`,
  ])("refuses %s", (p) => expect(isAllowedStaffMutation(p)).toBe(false));
});
