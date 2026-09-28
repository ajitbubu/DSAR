import { expect, test } from "@playwright/test";
import { DEV_PASSWORD, resetRateLimits, staffLogin, submitVerifiedRequest } from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

test("analyst signs in and sees source-wise discovery results (screen 6)", async ({ browser }) => {
  // Requester types someone else's customer ID; it must not pull in their record.
  const dp = await browser.newPage();
  const reference = await submitVerifiedRequest(dp, "priya.sharma@example.in", "CUST-2002");
  await dp.close();

  const page = await browser.newPage();
  await staffLogin(page, "analyst@acme.example.test");
  await expect(page.getByRole("heading", { name: "Privacy operations" })).toBeVisible();
  await page.getByRole("link", { name: reference }).click();
  await page.waitForURL(/\/ops\/cases\/[0-9a-f-]+$/);
  // Identity resolution runs in the worker right after verification.
  await expect(async () => {
    await page.reload();
    await expect(page.getByText("Claimed, not used")).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 45_000 });

  await page.getByRole("link", { name: "Discovery", exact: true }).click();
  await page.waitForURL(/\/discovery$/);
  // The worker runs discovery asynchronously; poll until all sources have reported.
  await expect(async () => {
    await page.reload();
    await expect(page.getByText(/3 records found across 2 sources/)).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 45_000 });

  const crm = page.getByRole("region", { name: "CRM (mock)" });
  const docs = page.getByRole("region", { name: "Document store (mock)" });
  await expect(crm.getByText("crm:contact:c-1001")).toBeVisible();
  await expect(crm.getByText("crm:invoice:i-5001")).toBeVisible();
  await expect(docs.getByText("docs:file:d-3001")).toBeVisible();
  await expect(page.getByText("crm:contact:c-2002")).toHaveCount(0);
  expect(await page.evaluate(() => document.cookie)).toBe("");

  const caseUrl = page.url().replace(/\/discovery$/, "");
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL("http://localhost:3000/");

  // Another tenant's staff can't see the case, even with its exact URL.
  await staffLogin(page, "auditor@globex.example.test", new URL(caseUrl).pathname);
  await expect(page.getByRole("heading", { name: "404" })).toBeVisible();
});

test("login ignores off-site return targets", async ({ page }) => {
  await page.goto("/api/auth/login?returnTo=https://evil.example/ops");
  await page.getByLabel(/username or email/i).fill("auditor@acme.example.test");
  await page.getByLabel("Password", { exact: true }).fill(DEV_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL("http://localhost:3000/ops");
});

test("ops pages require a staff session", async ({ page }) => {
  await page.goto("/ops");
  await expect(page).toHaveURL(/localhost:8080\/realms\/idprivacy/);
});

test("logout is CSRF-protected", async ({ request }) => {
  const res = await request.post("/api/auth/logout", {
    headers: { Origin: "https://evil.example", "Content-Type": "application/json" }, data: {},
  });
  expect(res.status()).toBe(403);
});
