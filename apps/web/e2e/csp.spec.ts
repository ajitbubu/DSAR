import { type Page, expect, test } from "@playwright/test";

/**
 * Regression: statically prerendered pages (the landing page, the 404 page) were served
 * without the per-request CSP nonce, so the browser blocked every Next.js script on them.
 * Also guards the favicon (it used to 404 on every page). Found while fixing TODOS item 8.
 */
async function problemsOn(page: Page, path: string): Promise<string[]> {
  const problems: string[] = [];
  const onConsole = (m: { type(): string; text(): string }) => {
    if (m.type() === "error" && !m.text().includes("status of 404")) problems.push(m.text().slice(0, 120));
  };
  const onResponse = (r: { status(): number; url(): string }) => {
    if (r.status() >= 400 && !r.url().endsWith(path)) problems.push(`${r.status()} ${r.url()}`);
  };
  page.on("console", onConsole);
  page.on("response", onResponse);
  await page.goto(path, { waitUntil: "networkidle" });
  page.off("console", onConsole);
  page.off("response", onResponse);
  return problems;
}

for (const path of ["/", "/r/acme", "/this-page-does-not-exist"]) {
  test(`${path} loads with no CSP violations or failed resources`, async ({ page }) => {
    expect(await problemsOn(page, path)).toEqual([]);
  });
}
