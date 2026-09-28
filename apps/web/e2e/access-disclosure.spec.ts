import { expect, test } from "@playwright/test";
import { resetRateLimits, signOut, staffLogin, submitVerifiedAccessRequest } from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

/**
 * Access milestone A2 through the real stack: discovery → analyst exports and withholds a
 * field → submits (the processing register covers both systems) → a separate approver
 * authorises the disclosure. Auditors never see exported content.
 */
test("right to access: disclosure review and approval", async ({ browser, request }) => {
  test.setTimeout(150_000);
  const reference = await submitVerifiedAccessRequest(request, "priya.sharma@example.in");

  const staff = await browser.newPage();
  await staffLogin(staff, "analyst@acme.example.test");
  await expect(async () => {
    await staff.reload();
    await expect(staff.getByRole("link", { name: reference })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 30_000 });
  await staff.getByRole("link", { name: reference }).click();
  await staff.waitForURL(/\/ops\/cases\/[0-9a-f-]+$/);
  const caseUrl = staff.url();

  await staff.goto(`${caseUrl}/disclosure`);
  await expect(async () => {  // discovery runs in the worker
    await staff.reload();
    await expect(staff.getByRole("button", { name: "Start review" })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 60_000 });
  await staff.getByRole("button", { name: "Start review" }).click();
  await staff.getByRole("button", { name: "Export records" }).click();
  await expect(staff.getByText(/Export round 1: ready · 3 records/)).toBeVisible({ timeout: 45_000 });

  const contact = staff.getByRole("region", { name: "mock-crm crm.contact" });
  await expect(contact.getByRole("cell", { name: "Pune" })).toBeVisible();
  await contact.getByRole("button", { name: "Withhold City" }).click();
  await expect(contact.getByText(/Withheld · Contains another person/)).toBeVisible();
  await staff.getByRole("button", { name: "Submit for approval" }).click();
  await expect(staff.getByText("Awaiting approval")).toBeVisible();
  await signOut(staff);

  await staffLogin(staff, "approver@acme.example.test", new URL(`${caseUrl}/approval`).pathname);
  await expect(staff.getByRole("heading", { name: "Authorise this disclosure" })).toBeVisible();
  await expect(staff.getByText(/releases 3 of 3 records .* 0 records and 1 field withheld/)).toBeVisible();
  await staff.getByRole("button", { name: "Approve" }).click();
  await expect(staff.locator("main p .status").first()).toHaveText("Approved");
  await signOut(staff);

  await staffLogin(staff, "auditor@acme.example.test", new URL(`${caseUrl}/disclosure`).pathname);
  await expect(staff.getByText("Your role can't view exported personal data.")).toBeVisible();
  await expect(staff.getByText("Pune")).toHaveCount(0);
});
