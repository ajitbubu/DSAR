import { type Page, expect, test } from "@playwright/test";

async function fillForm(page: Page, email: string) {
  await page.goto("/r/acme");
  await page.getByLabel("Full name").fill("E2E Requester");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Customer or account ID").fill("CUST-2002");
  await page.getByLabel(/I agree/).check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Confirm it's you" })).toBeVisible();
}

async function devCode(page: Page): Promise<string> {
  const note = await page.locator(".dev-note strong").textContent();
  expect(note).toMatch(/^\d{6}$/);
  return note!;
}

test("screens 1–3: submit, verify with OTP, track, withdraw", async ({ page }) => {
  await fillForm(page, `e2e-${Date.now()}@example.in`);
  await expect(page).toHaveURL(/\/r\/acme\/verify$/); // no ids or tokens in the URL
  const reference = await page.locator(".case-id").textContent();
  expect(reference).toMatch(/^DPR-\d{4}-[0-9A-Z]{6}$/);

  await page.getByLabel("Verification code").fill("000000");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator(".alert.error-box")).toContainText("isn't right");

  await page.getByLabel("Verification code").fill(await devCode(page));
  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page).toHaveURL(/\/r\/acme\/status$/);
  await expect(page.getByText(reference!)).toBeVisible();
  await expect(page.locator(".badge")).toHaveText("In progress");
  expect(await page.evaluate(() => document.cookie)).toBe(""); // all cookies httpOnly

  await page.getByRole("button", { name: "Withdraw request" }).click();
  await page.getByRole("button", { name: "Yes, withdraw" }).click();
  await expect(page.getByRole("heading", { name: "Request withdrawn" })).toBeVisible();
  await expect(page.locator(".badge")).toHaveText("Cancelled");
});

test("client-side validation blocks an incomplete form", async ({ page }) => {
  await page.goto("/r/acme");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByText("Enter your full name.")).toBeVisible();
  await expect(page.getByText("Enter your email address.")).toBeVisible();
  await expect(page).toHaveURL(/\/r\/acme$/);
});

test("tracking page without a session shows an expiry message", async ({ page }) => {
  await page.goto("/r/acme/status");
  await expect(page.getByRole("heading", { name: "Your tracking session has ended" })).toBeVisible();
});

test("BFF rejects cross-site state changes", async ({ request }) => {
  const res = await request.post("/api/public/requests", {
    headers: { Origin: "https://evil.example", "Content-Type": "application/json" },
    data: { intakeSlug: "acme" },
  });
  expect(res.status()).toBe(403);
});
