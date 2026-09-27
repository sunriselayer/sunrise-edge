import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: "./test/validator/wrangler.sql-test.jsonc" },
  })],
  test: { include: ["test/validator/sql-host.test.ts", "test/validator/ingress-policy.test.ts"] },
});
