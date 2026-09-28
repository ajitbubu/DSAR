import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type APIRequestContext, type Page, expect } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:8000";
const BFF_SECRET = process.env.E2E_BFF_SECRET ?? "dev-bff-shared-secret-change-me-0123456789";

/** The dev password lives only in the Keycloak realm fixture. */
export const DEV_PASSWORD: string = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../infra/compose/keycloak/idprivacy-realm.json",
                                    import.meta.url)), "utf8"),
).users[0].credentials[0].value;

export async function resetRateLimits(request: APIRequestContext) {
  const res = await request.post(`${API}/v1/test-support/rate-limits/reset`, {
    headers: { "X-Internal-Auth": BFF_SECRET },
  });
  expect(res.status()).toBe(204);
}

/** Submits and verifies an erasure request through the Data Principal screens. */
export async function submitVerifiedRequest(page: Page, email: string, customerId = ""): Promise<string> {
  await page.goto("/r/acme");
  await page.getByLabel("Full name").fill("E2E Requester");
  await page.getByLabel("Email address").fill(email);
  if (customerId) await page.getByLabel("Customer or account ID").fill(customerId);
  await page.getByLabel(/I agree/).check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Confirm it's you" })).toBeVisible();
  const reference = (await page.locator(".case-id").textContent())!;
  const code = (await page.locator(".dev-note strong").textContent())!;
  await page.getByLabel("Verification code").fill(code);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page).toHaveURL(/\/status$/);
  return reference;
}

export async function staffLogin(page: Page, username: string, path = "/ops") {
  await page.goto(path);
  await page.getByLabel(/username or email/i).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(DEV_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
}
