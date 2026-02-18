import { test, expect } from '@playwright/test'

test('cart persists after reload', async ({ page }) => {
  await page.goto('/')
  const count = page.locator('.cart-count')
  await expect(count).toHaveText('0')
  await page.locator('.product.card').first().click()
  await expect(count).toHaveText('1')
  await page.reload()
  await expect(count).toHaveText('1')
})
