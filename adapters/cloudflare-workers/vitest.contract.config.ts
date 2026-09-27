import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: "./test/validator/wrangler.contract-test.jsonc" },
  })],
  test: {
    include: ["test/validator/contract-lifecycle.test.ts"],
    testTimeout: 120_000,
  },
});
