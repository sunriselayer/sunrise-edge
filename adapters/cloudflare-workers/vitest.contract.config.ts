import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({
    experimental: { newConfig: { configPath: "./profiles/contract/cloudflare.config.ts" } },
    remoteBindings: false,
    // Vitest renames the Worker; absent scriptName binds to its local runner.
    miniflare: {
      durableObjects: {
        VALIDATOR_ZERO: { className: "ValidatorZero", useSQLite: true },
        VALIDATOR_ONE: { className: "ValidatorOne", useSQLite: true },
        VALIDATOR_TWO: { className: "ValidatorTwo", useSQLite: true },
        VALIDATOR_THREE: { className: "ValidatorThree", useSQLite: true },
      },
    },
  })],
  test: {
    include: ["test/validator/contract-lifecycle.test.ts"],
    testTimeout: 120_000,
  },
});
