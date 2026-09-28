import { expect, test } from "@playwright/test";
import { resetRateLimits, staffLogin, submitVerifiedRequest } from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

test("analyst resolves manual review and submits for approval (screen 7)", async ({ browser }) => {
  const dp = await browser.newPage();
  const reference = await submitVerifiedRequest(dp, "priya.sharma@example.in");
  await dp.close();

  const page = await browser.newPage();
  await staffLogin(page, "analyst@acme.example.test");
  await page.getByRole("link", { name: reference }).click();
  await page.waitForURL(/\/ops\/cases\/[0-9a-f-]+$/);
  await page.getByRole("link", { name: "Retention", exact: true }).click();
  await page.waitForURL(/\/retention$/);
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole("button", { name: "Start review" })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 20_000 });

  await page.getByRole("button", { name: "Start review" }).click();
  const submit = page.getByRole("button", { name: "Submit for approval" });
  await expect(submit).toBeDisabled();
  await expect(page.getByText(/Resolve 1 record/)).toBeVisible();

  const invoice = page.getByRole("row", { name: /crm:invoice:i-5001/ });
  await expect(invoice.getByText("Needs review")).toBeVisible();
  await invoice.getByRole("button", { name: "Change decision" }).click();
  await invoice.getByLabel("Reason (recorded in the audit trail)").fill("short");
  await invoice.getByRole("button", { name: "Save decision" }).click();
  await expect(invoice.getByText(/at least 10 characters/)).toBeVisible();
  await invoice.getByLabel("Reason (recorded in the audit trail)")
    .fill("Unpaid invoice must be kept for GST records.");
  await invoice.getByRole("button", { name: "Save decision" }).click();
  await expect(invoice.getByText("Retain", { exact: true })).toBeVisible();
  await expect(invoice.getByText("History (2)")).toBeVisible();

  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(page.getByText("Awaiting approval")).toBeVisible();
  await expect(page.getByRole("button", { name: "Change decision" })).toHaveCount(0);
});

test("auditors can read retention but not change it", async ({ page }) => {
  await staffLogin(page, "auditor@acme.example.test");
  await page.getByRole("link", { name: /DPR-/ }).first().click();
  await page.getByRole("link", { name: "Retention", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Legal hold" })).toBeVisible();
  await page.getByLabel("Matter reference").fill("LIT-X");
  await page.getByLabel("Reason").fill("Auditors must not be able to do this.");
  await page.getByRole("button", { name: "Place legal hold" }).click();
  await expect(page.getByText("Your role can't place legal holds.")).toBeVisible();
});

test("staff proxy refuses non-allowlisted API paths", async ({ request }) => {
  const res = await request.post("/api/staff/v1/audit/verify", {
    headers: { Origin: "http://localhost:3000", "Content-Type": "application/json" }, data: {},
  });
  expect(res.status()).toBe(404);
});
