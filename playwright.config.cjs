// @ts-check
const { defineConfig } = require('@playwright/test');

/**
 * Playwright configuration for API gateway E2E tests.
 * The webServer block starts the compiled NestJS server before tests run.
 */
module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4000',
    extraHTTPHeaders: { 'Content-Type': 'application/json' },
  },
  webServer: {
    command: 'node 2027-online-shop/apps/api-gateway/dist/main.js',
    url: 'http://localhost:4000',
    reuseExistingServer: false,
    timeout: 20_000,
    env: {
      PORT: '4000',
      // Use SQLite-compatible in-memory stub so E2E tests don't need Postgres.
      // PrismaService connection errors are handled gracefully in tests.
      DATABASE_URL: 'file:/tmp/e2e-test.db',
    },
  },
});
