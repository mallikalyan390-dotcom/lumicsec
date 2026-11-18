import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "**/coverage/**", "**/playwright-report/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }]
    }
  },
  {
    files: ["apps/api/src/routes/api-specs.ts", "packages/web-security-engine/src/**/*.ts"],
    rules: { "no-control-regex": "off" },
  },
  {
    files: ["packages/web-security-engine/src/analysis.ts"],
    rules: { "no-empty": ["error", { "allowEmptyCatch": true }] },
  }
);
