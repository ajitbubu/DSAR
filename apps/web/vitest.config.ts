import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./", import.meta.url)),
      "server-only": fileURLToPath(new URL("./test/server-only-stub.ts", import.meta.url)),
    },
  },
  test: {
    include: ["**/*.test.ts", "**/*.test.tsx"],
    exclude: ["node_modules", ".next", "e2e"],
    coverage: {
      provider: "v8",
      include: ["lib/**", "app/**"],
      exclude: ["**/*.test.*"],
      reporter: ["text-summary", "json-summary"],
      // Floor, not a target: first measured value minus 2 (raise as tests are added).
      thresholds: { lines: 11, statements: 11 },
    },
  },
});
