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

const MOCKS = process.env.E2E_MOCK_CONNECTORS_URL ?? "http://localhost:8100";

/** Resets rate limits and the mock systems' records (fulfilment really deletes them). */
export async function resetRateLimits(request: APIRequestContext) {
  const res = await request.post(`${API}/v1/test-support/rate-limits/reset`, {
    headers: { "X-Internal-Auth": BFF_SECRET },
  });
  expect(res.status()).toBe(204);
  expect((await request.post(`${MOCKS}/__test__/reset`)).status()).toBe(200);
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

/** Analyst opens the case, resolves the invoice's manual review and submits for approval. */
export async function analystSubmitsForApproval(page: Page, reference: string): Promise<string> {
  await staffLogin(page, "analyst@acme.example.test");
  await page.getByRole("link", { name: reference }).click();
  await page.waitForURL(/\/ops\/cases\/[0-9a-f-]+$/);
  const caseUrl = page.url();
  await page.goto(`${caseUrl}/retention`);
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole("button", { name: "Start review" })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 45_000 });
  await page.getByRole("button", { name: "Start review" }).click();
  const invoice = page.getByRole("row", { name: /crm:invoice:i-5001/ });
  await invoice.getByRole("button", { name: "Change decision" }).click();
  await invoice.getByLabel("Reason (recorded in the audit trail)")
    .fill("Unpaid invoice must be kept for GST records.");
  await invoice.getByRole("button", { name: "Save decision" }).click();
  await expect(invoice.getByText("Retain", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await expect(page.getByText("Awaiting approval")).toBeVisible();
  return caseUrl;
}

export async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL("http://localhost:3000/");
}

/**
 * Submits and verifies an access request straight through the public API, as the BFF would.
 * The requester-facing choice of right arrives with access milestone A3.
 */
export async function submitVerifiedAccessRequest(request: APIRequestContext, email: string): Promise<string> {
  const headers = { "X-Internal-Auth": BFF_SECRET, "X-Client-IP": "203.0.113.50" };
  const res = await request.post(`${API}/v1/public/requests`, {
    headers,
    data: {
      intakeSlug: "acme", rights: ["ACCESS"], fullName: "E2E Requester",
      contact: { channel: "EMAIL", value: email }, additionalIdentifiers: [],
      residencyClaim: "IN", consentToProcess: true,
    },
  });
  expect(res.status()).toBe(202);
  const { displayId, challengeId } = await res.json();
  const otp = await request.get(`${API}/v1/test-support/otp/${challengeId}`, { headers });
  const confirm = await request.post(`${API}/v1/public/verifications/${challengeId}/confirm`, {
    headers, data: { code: (await otp.json()).code },
  });
  expect(confirm.status()).toBe(200);
  return displayId;
}
