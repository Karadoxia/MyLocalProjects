/** @type {import('@playwright/test').PlaywrightTestConfig} */
module.exports = {
  testDir: './e2e',
  timeout: 30 * 1000,
  use: {
    headless: true,
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:5002',
    ignoreHTTPSErrors: true,
  },
  reporter: [['list']],
};
