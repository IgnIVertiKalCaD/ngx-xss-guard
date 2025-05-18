module.exports = {
  preset: "jest-preset-angular",
  roots: ["<rootDir>/src/lib"],
  testMatch: ["**/*.spec.ts"],
  setupFilesAfterEnv: ["<rootDir>/src/test.ts"],
  collectCoverage: true,
  coverageReporters: ["html", "text-summary"],
  coverageThreshold: {
    global: {
      statements: 80,
      branches: 80,
      functions: 80,
      lines: 80,
    },
  },
  moduleNameMapper: {
    "ngx-xss-guard": "<rootDir>/dist/ngx-xss-guard",
  },
};
