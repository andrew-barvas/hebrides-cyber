// Next.js 16 removed the `next lint` command (see package.json's "lint"
// script, now plain `eslint .`) — this is the standard flat-config
// replacement, using @eslint/eslintrc's compat layer to keep using
// eslint-config-next's rule sets without waiting for a native flat-config
// release of every rule set.
import { FlatCompat } from "@eslint/eslintrc";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

const eslintConfig = [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    ignores: [".next/**", "node_modules/**", "playwright-report/**", "test-results/**"],
  },
];

export default eslintConfig;
