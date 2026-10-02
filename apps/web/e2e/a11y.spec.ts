import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";
import { resetRateLimits, staffLogin } from "./helpers";

test.beforeEach(async ({ request }) => resetRateLimits(request));

/** WCAG 2.1 A and AA rules only; a violation names the rule and the offending nodes. */
async function expectNoViolations(page: Page, screen: string) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const summary = violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
  expect(summary, `${screen} has accessibility violations`).toEqual([]);
}

test("data principal screens meet WCAG 2.1 AA", async ({ page }) => {
  await page.goto("/r/acme");
  await expectNoViolations(page, "request form");

  await page.getByRole("button", { name: "Continue" }).click();  // empty submit: errors shown
  await expectNoViolations(page, "request form with validation errors");

  await page.getByLabel("Full name").fill("Priya Sharma");
  await page.getByLabel("Email address").fill("priya.sharma@example.in");
  await page.getByLabel(/I agree/).check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Confirm it's you" })).toBeVisible();
  await expectNoViolations(page, "verify screen");

  await page.getByLabel("Verification code").fill((await page.locator(".dev-note strong").textContent())!);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page).toHaveURL(/\/status$/);
  await expectNoViolations(page, "status screen");
});

test("staff console screens meet WCAG 2.1 AA", async ({ page }) => {
  await staffLogin(page, "analyst@acme.example.test");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expectNoViolations(page, "case list");

  await page.locator("a.mono, td a").first().click();
  await page.waitForURL(/\/ops\/cases\/[0-9a-f-]+$/);
  const caseUrl = page.url();
  await expectNoViolations(page, "case overview");
  for (const tab of ["discovery", "retention", "audit"]) {
    await page.goto(`${caseUrl}/${tab}`);
    await expectNoViolations(page, `case ${tab}`);
  }
});
