import { test, expect } from '@playwright/test'

test('add to cart updates UI count', async ({ page }) => {
  // ensure clean state
  await page.request.delete('/api/cart')
  await page.goto('/')
  const count = page.locator('.cart-count')
  await expect(count).toHaveText('0')
  await page.locator('.product.card').first().click()
  await expect(count).toHaveText('1')
  // hero CTA also works
  await page.locator('.btn.primary').click()
  await expect(count).toHaveText('2')
})
