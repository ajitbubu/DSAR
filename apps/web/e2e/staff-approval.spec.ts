import { expect, test } from "@playwright/test";
import {
  analystSubmitsForApproval,
  resetRateLimits,
  signOut,
  staffLogin,
  submitVerifiedRequest,
} from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

test("a separate approver authorises the decisions (screen 8)", async ({ browser }) => {
  const dp = await browser.newPage();
  const reference = await submitVerifiedRequest(dp, "priya.sharma@example.in");
  await dp.close();

  const page = await browser.newPage();
  const caseUrl = await analystSubmitsForApproval(page, reference);

  // The analyst isn't an approver: the queue is closed to them.
  await page.goto("/ops/approvals");
  await expect(page.getByText("Only approvers can see the approval queue.")).toBeVisible();
  await signOut(page);

  await staffLogin(page, "approver@acme.example.test", "/ops/approvals");
  await expect(page.getByRole("heading", { name: "Approval queue" })).toBeVisible();
  await page.getByRole("link", { name: reference }).click();
  await expect(page).toHaveURL(`${caseUrl}/approval`);
  await expect(page.getByText(/act on 2 records marked Delete/)).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("Approved", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await expect(page.locator("li").filter({ hasText: "approved" })).toHaveCount(1);
});

test("a rejection sends the case back for rework", async ({ browser }) => {
  const dp = await browser.newPage();
  const reference = await submitVerifiedRequest(dp, "priya.sharma@example.in");
  await dp.close();

  const page = await browser.newPage();
  const caseUrl = await analystSubmitsForApproval(page, reference);
  await signOut(page);

  await staffLogin(page, "approver@acme.example.test", new URL(`${caseUrl}/approval`).pathname);
  await page.getByRole("button", { name: "Reject" }).click();
  await expect(page.getByText(/at least 10 characters/)).toBeVisible();
  await page.getByLabel("Comment (required to reject)").fill("Cite the GST section for the invoice.");
  await page.getByRole("button", { name: "Reject" }).click();
  await expect(page.getByText("Returned for rework")).toBeVisible();
  await signOut(page);

  await staffLogin(page, "analyst@acme.example.test", new URL(`${caseUrl}/retention`).pathname);
  await page.getByRole("button", { name: "Resume review" }).click();
  await expect(page.getByText("Under review")).toBeVisible();
});
