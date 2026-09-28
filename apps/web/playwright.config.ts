import { defineConfig, devices } from "@playwright/test";

/** Runs against the Docker Compose stack (`make up`); API runs with IDP_ENV=test. */
export default defineConfig({
  testDir: "./e2e",
  // Specs wait on the real async pipeline (outbox → worker → connectors); leave headroom.
  timeout: 90_000,
  // Server-rendered pages call the API; allow for a busy host rather than flaking.
  expect: { timeout: 15_000 },
  // One shared stack with real rate limits: run serially, and each spec resets limits.
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
  },
  // Locally, use the installed Chrome (clean, isolated profile); CI installs Chromium.
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], channel: process.env.CI ? undefined : "chrome" },
    },
  ],
});
