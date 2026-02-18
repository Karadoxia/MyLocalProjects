import { test, expect } from '@playwright/test'

test('homepage shows hero and static UI', async ({ page }) => {
  await page.request.delete('/api/cart')
  await page.goto('/')
  await expect(page.locator('.hero-title')).toContainText('Level up with')
  await expect(page.locator('.site-footer')).toHaveText(/© 2026/)
})
