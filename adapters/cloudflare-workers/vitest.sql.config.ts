import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({
    experimental: { newConfig: { configPath: "./profiles/sql/cloudflare.config.ts" } },
    remoteBindings: false,
    // Vitest renames the Worker; absent scriptName binds to its local runner.
    miniflare: {
      durableObjects: {
        SQL_PROBE: { className: "SqlProbe", useSQLite: true },
      },
    },
  })],
  test: { include: ["test/validator/sql-host.test.ts", "test/validator/ingress-policy.test.ts"] },
});
