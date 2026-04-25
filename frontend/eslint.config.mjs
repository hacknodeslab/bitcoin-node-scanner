import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const nextCoreWebVitals = require("eslint-config-next/core-web-vitals");
const nextTypescript = require("eslint-config-next/typescript");
const designSystem = require("./eslint-rules/index.cjs");

const config = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    plugins: {
      "design-system": designSystem,
    },
    rules: {
      "design-system/no-banned-classnames": "error",
      "design-system/no-banned-imports": "error",
      "design-system/only-jetbrains-mono-font": "error",
      "design-system/no-inline-color": "error",
      "design-system/primary-allowlist": "error",
    },
  },
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "out/**",
      "dist/**",
      "next-env.d.ts",
    ],
  },
];

export default config;
