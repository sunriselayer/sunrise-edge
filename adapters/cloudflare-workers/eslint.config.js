import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "test/env.d.ts",
      "cloudflare-workers/test/env.d.ts",
      "worker-configuration.d.ts",
      "validator-configuration.d.ts",
      "certified-configuration.d.ts",
      "cloudflare-workers/certified-configuration.d.ts",
      "cloudflare-workers/validator-configuration.d.ts",
      "cloudflare-workers/worker-configuration.d.ts",
      "cloudflare-workers/test/validator/sql-env.d.ts",
      "test/validator/sql-env.d.ts",
      "test/validator/contract-env.d.ts",
      "cloudflare-workers/test/validator/contract-env.d.ts",
      "cloudflare-workers/src/validator/generated/**",
      "src/validator/generated/**",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
  {
    basePath: "../",
    files: ["shared/**/*.ts"],
    extends: [
      eslint.configs.recommended,
      ...tseslint.configs.recommendedTypeChecked,
    ],
    languageOptions: {
      parserOptions: {
        project: "./cloudflare-workers/tsconfig.json",
        tsconfigRootDir: new URL("..", import.meta.url).pathname,
      },
    },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
);
