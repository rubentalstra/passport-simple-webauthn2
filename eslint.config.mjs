import globals from "globals";
import js from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import prettierPlugin from "eslint-plugin-prettier";
import prettierConfig from "eslint-config-prettier";
import jestPlugin from "eslint-plugin-jest"; // Import Jest plugin

/** @type {import('eslint').Linter.FlatConfig[]} */
export default [
  {
    files: ["src/**/*.{js,mjs,cjs,ts}"], // Restrict to src/ directory
    ignores: [
      "node_modules/",
      "dist/",
      "coverage/",
      "docs/",
      "src/**/*.test.ts", // Exclude all test files
      "test/**/*.ts" // Exclude all files within test directories
    ],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.json",
        sourceType: "module",
        ecmaVersion: "latest",
      },
      globals: globals.node,
    },
    plugins: {
      "@typescript-eslint": tseslint,
      prettier: prettierPlugin,
    },
    rules: {
      ...js.configs.recommended.rules, // Enable recommended JS rules
      ...tseslint.configs.recommended.rules, // Enable recommended TS rules
      ...prettierConfig.rules, // Enable Prettier rules

      "prettier/prettier": "error", // Enforce Prettier formatting
      "no-console": "warn",
      "semi": ["error", "always"],
      "quotes": ["error", "double"],
      "comma-dangle": ["error", "always-multiline"],
      "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
      "@typescript-eslint/explicit-function-return-type": "warn",
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-var-requires": "error",
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
];