import { test, expect } from '@playwright/test'

test('metrics endpoint exposes cart metrics', async ({ request }) => {
  const r = await request.get('/metrics')
  expect(r.status()).toBe(200)
  const body = await r.text()
  expect(body).toMatch(/cart_items_total\s+\d+/)
  expect(body).toMatch(/cart_unique_items\s+\d+/)
})
