/** @type {import('jest').Config} */
module.exports = {
  // ESM rather than the default CommonJS transform, matching the source this
  // package ships. Requires NODE_OPTIONS=--experimental-vm-modules, set in the
  // `test` script.
  preset: "ts-jest/presets/default-esm",
  extensionsToTreatAsEsm: [".ts"],
  testEnvironment: "node",
  transform: {
    "^.+\\.ts$": ["ts-jest", { useESM: true }],
  },
  testMatch: ["<rootDir>/src/**/__tests__/**/*.test.ts"],
  collectCoverageFrom: ["src/**/*.ts", "!src/**/__tests__/**", "!src/index.ts"],
  // A package on the sign-in path of four products. The floor is high because
  // the uncovered branch in an auth library is, by construction, a rejection
  // path — which is the half that matters.
  coverageThreshold: {
    global: { statements: 90, branches: 85, functions: 90, lines: 90 },
  },
};
