import { test, expect } from '@playwright/test'

test('backup and restore cart via API', async ({ page }) => {
  // ensure clean state
  await page.request.delete('/api/cart')
  await page.goto('/')

  // add an item
  await page.locator('.product.card').nth(1).click()
  await expect(page.locator('.cart-count')).toHaveText('1')

  // request a backup
  const backupRes = await page.request.post('/api/backup')
  expect(backupRes.status()).toBe(201)
  const backupJson = await backupRes.json()
  expect(backupJson.backedUp).toMatch(/^cart-/)

  // clear cart and verify empty
  await page.request.delete('/api/cart')
  await page.reload()
  await expect(page.locator('.cart-count')).toHaveText('0')

  // restore from backup
  const restoreRes = await page.request.post('/api/restore', { data: { file: backupJson.backedUp } })
  expect(restoreRes.status()).toBe(200)

  await page.reload()
  await expect(page.locator('.cart-count')).toHaveText('1')
})
