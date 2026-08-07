import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    ignores: ["node_modules/**", "coverage/**", "dist/**"],
  },
  js.configs.recommended,
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
      globals: {
        // node:crypto's Buffer, and nothing else. Listed explicitly rather than
        // pulled from `globals` so this package keeps its zero-dependency claim
        // down to its dev tooling.
        Buffer: "readonly",
        URLSearchParams: "readonly",
      },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // `--fix` is deliberately not wired into any script here: a build that
      // rewrites tracked sources hides from review the very errors review
      // exists to catch, and leaves the fix uncommitted so it returns on the
      // next checkout.
    },
  },
  {
    files: ["src/**/__tests__/**/*.ts"],
    languageOptions: {
      globals: {
        describe: "readonly",
        it: "readonly",
        expect: "readonly",
        beforeEach: "readonly",
        jest: "readonly",
      },
    },
  },
];
