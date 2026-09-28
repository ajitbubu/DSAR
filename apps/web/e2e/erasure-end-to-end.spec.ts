import { expect, test } from "@playwright/test";
import { resetRateLimits, signOut, staffLogin } from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

/**
 * The whole first vertical slice, through the real stack:
 * submit → OTP → discovery → review with one override → separate approver approves →
 * fulfilment → verification → evidence download → requester sees completion → CLOSED.
 */
test("right to erasure, end to end", async ({ browser }) => {
  test.setTimeout(180_000);

  // 1–3. The Data Principal submits and verifies. Their tab stays open to track.
  const requester = await browser.newPage();
  await requester.goto("/r/acme");
  await requester.getByLabel("Full name").fill("Priya Sharma");
  await requester.getByLabel("Email address").fill("priya.sharma@example.in");
  await requester.getByLabel("Customer or account ID").fill("CUST-2002"); // someone else's
  await requester.getByLabel(/I agree/).check();
  await requester.getByRole("button", { name: "Continue" }).click();
  const reference = (await requester.locator(".case-id").textContent())!;
  await requester.getByLabel("Verification code").fill(
    (await requester.locator(".dev-note strong").textContent())!);
  await requester.getByRole("button", { name: "Verify" }).click();
  await expect(requester.locator(".badge")).toHaveText("In progress");

  // 4–9. Jurisdiction, identity resolution, discovery and retention run in the worker.
  const staff = await browser.newPage();
  await staffLogin(staff, "analyst@acme.example.test");
  await staff.getByRole("link", { name: reference }).click();
  await staff.waitForURL(/\/ops\/cases\/[0-9a-f-]+$/);
  const caseUrl = staff.url();
  await expect(async () => {  // identity resolution runs in the worker
    await staff.reload();
    await expect(staff.getByText("Claimed, not used")).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 45_000 });
  await staff.goto(`${caseUrl}/discovery`);
  await expect(async () => {
    await staff.reload();
    await expect(staff.getByText(/3 records found across 2 sources/)).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 45_000 });
  await expect(staff.getByText("crm:contact:c-2002")).toHaveCount(0);

  // 10. Analyst review with one documented override.
  await staff.goto(`${caseUrl}/retention`);
  await expect(async () => {
    await staff.reload();
    await expect(staff.getByRole("button", { name: "Start review" })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 45_000 });
  await staff.getByRole("button", { name: "Start review" }).click();
  const invoice = staff.getByRole("row", { name: /crm:invoice:i-5001/ });
  await invoice.getByRole("button", { name: "Change decision" }).click();
  await invoice.getByLabel("Reason (recorded in the audit trail)")
    .fill("Unpaid invoice must be kept for GST records.");
  await invoice.getByRole("button", { name: "Save decision" }).click();
  await expect(invoice.getByText("Retain", { exact: true })).toBeVisible();
  await staff.getByRole("button", { name: "Submit for approval" }).click();
  await expect(staff.getByText("Awaiting approval")).toBeVisible();
  await signOut(staff);

  // 11. A separate approver authorises.
  await staffLogin(staff, "approver@acme.example.test", new URL(`${caseUrl}/approval`).pathname);
  await staff.getByRole("button", { name: "Approve" }).click();
  await expect(staff.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await signOut(staff);

  // 12–17. Fulfilment, verification, evidence and the completion response.
  await staffLogin(staff, "auditor@acme.example.test", new URL(caseUrl).pathname);
  await expect(async () => {
    await staff.reload();
    await expect(staff.locator("main p .status").first()).toHaveText("Closed", { timeout: 1000 });
  }).toPass({ timeout: 90_000 });

  await staff.goto(`${caseUrl}/fulfilment`);
  await expect(staff.getByText("succeeded 2")).toBeVisible();
  await staff.goto(`${caseUrl}/verification`);
  await expect(staff.locator(".status.ok").filter({ hasText: "pass" })).toHaveCount(3);
  await staff.goto(`${caseUrl}/evidence`);
  const [download] = await Promise.all([
    staff.waitForEvent("download"),
    staff.getByRole("link", { name: "Download package" }).click(),
  ]);
  expect(download.suggestedFilename()).toContain(reference);

  await staff.goto(`${caseUrl}/audit`);
  await expect(staff.getByText("communication.sent")).toBeVisible();
  await staff.getByRole("button", { name: "Verify hash chain" }).click();
  await expect(staff.getByText(/Chain intact/)).toBeVisible();

  // The requester's tracking page shows the outcome.
  await requester.reload();
  await expect(requester.getByRole("heading", { name: "Your request is closed" })).toBeVisible();
  await expect(requester.getByText(/2 records were deleted\./)).toBeVisible();
  await expect(requester.getByText(/1 record was kept: Retention is required/)).toBeVisible();
});
