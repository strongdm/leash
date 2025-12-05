import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const eslintConfig = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    ignores: [
      "node_modules/**",
      ".next/**",
      "out/**",
      "build/**",
      "next-env.d.ts",
    ],
  },
  {
    // Disable new stricter React 19.2 rules that flag common patterns
    rules: {
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/globals": "off",
    },
  },
];

export default eslintConfig;
