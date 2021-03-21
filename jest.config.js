/* eslint-disable */
module.exports = {
  collectCoverageFrom: [
    "**/*.{ts, tsx}",
    // Non-library folders/files
    "!**/node_modules/**",
    "!**/coverage/**",
    "!**/dist/**",
    "!jest.config.js",
  ],
  coverageDirectory: "./coverage",
  coverageReporters: ["lcov"],
  roots: ["src"],
  setupFiles: [],
  setupFilesAfterEnv: ["jest-extended"],
  transform: { "^.+\\.tsx?$": "ts-jest" },
};
