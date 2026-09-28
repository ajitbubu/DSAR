import { expect, test } from "@playwright/test";
import {
  analystSubmitsForApproval,
  resetRateLimits,
  signOut,
  staffLogin,
  submitVerifiedRequest,
} from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

test("verification passes and the evidence package downloads (screens 10–11)", async ({ browser }) => {
  const dp = await browser.newPage();
  const reference = await submitVerifiedRequest(dp, "priya.sharma@example.in");
  await dp.close();

  const page = await browser.newPage();
  const caseUrl = await analystSubmitsForApproval(page, reference);
  await signOut(page);
  await staffLogin(page, "approver@acme.example.test", new URL(`${caseUrl}/approval`).pathname);
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await signOut(page);

  await staffLogin(page, "auditor@acme.example.test", new URL(`${caseUrl}/evidence`).pathname);
  // Fulfilment → verification → evidence all run in the worker.
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole("link", { name: "Download package" })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 60_000 });
  await expect(page.getByText("Evidence ready")).toBeVisible();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("link", { name: "Download package" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^evidence-DPR-\d{4}-[0-9A-Z]{6}-package\.zip$/);
  const bytes = await (await download.createReadStream()).toArray();
  const buf = Buffer.concat(bytes as Buffer[]);
  expect(buf.subarray(0, 2).toString()).toBe("PK");

  await page.getByRole("link", { name: "Verification", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Round 1" })).toBeVisible();
  await expect(page.locator(".status.ok").filter({ hasText: "pass" })).toHaveCount(3);
});

test("analyst uploads supporting evidence; spoofed files are refused", async ({ page }) => {
  await staffLogin(page, "analyst@acme.example.test");
  await page.getByRole("link", { name: /DPR-/ }).first().click();
  await page.getByRole("link", { name: "Evidence", exact: true }).click();

  await page.getByLabel(/Supporting document/).setInputFiles({
    name: "court-order.pdf", mimeType: "application/pdf",
    buffer: Buffer.from("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"),
  });
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByText("Uploaded.")).toBeVisible();
  await expect(page.getByRole("link", { name: /application\/pdf/ }).first()).toBeVisible();

  await page.getByLabel(/Supporting document/).setInputFiles({
    name: "invoice.pdf", mimeType: "application/pdf",
    buffer: Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32)]),
  });
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByText(/contents must match the type/)).toBeVisible();
});
