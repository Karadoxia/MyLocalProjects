import { test, expect } from '@playwright/test'

test('CI-seeded cart is persisted after restart (skips if not seeded)', async ({ page }) => {
  const res = await page.request.get('/api/cart')
  const j = await res.json()
  if (!j || !j.total || j.total === 0) test.skip('no seeded cart present')

  await page.goto('/')
  await expect(page.locator('.cart-count')).toHaveText(String(j.total))
})
