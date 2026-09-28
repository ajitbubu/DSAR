import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { resetRateLimits, signOut, staffLogin } from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

/**
 * The Right to Access slice through the real stack: the requester asks for a copy →
 * OTP → discovery → analyst exports and withholds a field → a separate approver
 * authorises → report built → requester downloads it → case CLOSED → the requester
 * returns later with their reference and a new code.
 */
test("right to access, end to end", async ({ browser }) => {
  test.setTimeout(180_000);

  const requester = await browser.newPage();
  await requester.goto("/r/acme");
  await requester.getByLabel("Get a copy of my data").check();
  await requester.getByLabel("Full name").fill("Priya Sharma");
  await requester.getByLabel("Email address").fill("priya.sharma@example.in");
  await requester.getByLabel(/I agree/).check();
  await requester.getByRole("button", { name: "Continue" }).click();
  const reference = (await requester.locator(".case-id").textContent())!;
  await requester.getByLabel("Verification code").fill(
    (await requester.locator(".dev-note strong").textContent())!);
  await requester.getByRole("button", { name: "Verify" }).click();
  await expect(requester.locator(".badge")).toHaveText("In progress");

  // Analyst: export, withhold the city, submit.
  const staff = await browser.newPage();
  await staffLogin(staff, "analyst@acme.example.test");
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

  // A separate approver authorises the disclosure.
  await staffLogin(staff, "approver@acme.example.test", new URL(`${caseUrl}/approval`).pathname);
  await expect(staff.getByRole("heading", { name: "Authorise this disclosure" })).toBeVisible();
  await expect(staff.getByText(/releases 3 of 3 records .* 0 records and 1 field withheld/)).toBeVisible();
  await staff.getByRole("button", { name: "Approve" }).click();
  await expect(staff.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await signOut(staff);

  // The worker builds the report and closes the case. Auditors never see content.
  await staffLogin(staff, "auditor@acme.example.test", new URL(caseUrl).pathname);
  await expect(async () => {
    await staff.reload();
    await expect(staff.locator("main p .status").first()).toHaveText("Closed", { timeout: 1000 });
  }).toPass({ timeout: 90_000 });
  await staff.goto(`${caseUrl}/disclosure`);
  await expect(staff.getByText("Your role can't view exported personal data.")).toBeVisible();

  // The requester downloads their copy: their data, without what was withheld.
  await requester.reload();
  await expect(requester.getByRole("heading", { name: "Your request is closed" })).toBeVisible();
  await expect(requester.getByText(/Your copy of the personal data we hold/)).toBeVisible();
  const [download] = await Promise.all([
    requester.waitForEvent("download"),
    requester.getByRole("link", { name: "Download (readable page)" }).click(),
  ]);
  expect(download.suggestedFilename()).toBe(`${reference}-my-data.html`);
  const html = readFileSync((await download.path())!, "utf8");
  expect(html).toContain("Priya Sharma");
  expect(html).not.toContain("Pune");

  // Days later, in a fresh browser: back in with the reference and a new code.
  const later = await (await browser.newContext()).newPage();
  await later.goto("/r/acme/signin");
  await later.getByLabel("Request reference").fill(reference);
  await later.getByLabel("Email address").fill("priya.sharma@example.in");
  await later.getByRole("button", { name: "Send code" }).click();
  await expect(later.getByRole("heading", { name: "Confirm it's you" })).toBeVisible();
  await later.getByLabel("Verification code").fill((await later.locator(".dev-note strong").textContent())!);
  await later.getByRole("button", { name: "Verify" }).click();
  await expect(later.getByRole("heading", { name: "Your request is closed" })).toBeVisible();
  await expect(later.getByText(/4 downloads left/)).toBeVisible();
});
