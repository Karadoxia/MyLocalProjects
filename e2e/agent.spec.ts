import { test, expect } from '@playwright/test'
import http from 'http'

test('agent prompt returns fallback prompt', async ({ request }) => {
  const r = await request.get('/api/agent/prompt')
  expect(r.status()).toBe(200)
  const j = await r.json()
  expect(typeof j.prompt).toBe('string')
  expect(j.prompt).toMatch(/Orchestrator|dev fallback/i)
})

test('agent scrape returns title from an internal target', async ({ request }) => {
  // start a tiny HTTP server as the scrape target
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end('<html><head><title>Playwright Agent Page</title></head><body>ok</body></html>')
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  // @ts-ignore - address() typing in Node.js
  const port = (server.address() as any).port
  const target = `http://127.0.0.1:${port}/`

  const resp = await request.post('/api/agent/scrape', { data: { url: target } })
  expect(resp.status()).toBe(200)
  const body = await resp.json()
  expect(body.title).toBe('Playwright Agent Page')

  server.close()
})

test('agent demo endpoint creates a cart item and backup', async ({ request }) => {
  const r = await request.post('/api/agent/demo')
  expect(r.status()).toBe(200)
  const j = await r.json()
  expect(j.ok).toBe(true)
  expect(j.item).toBe('agent-demo')

  const cart = await request.get('/api/cart')
  const cj = await cart.json()
  expect(cj.items.find((i: any) => i.id === 'agent-demo')).toBeTruthy()

  const backups = await request.get('/api/backups')
  const bj = await backups.json()
  expect(Array.isArray(bj.backups)).toBe(true)
  expect(bj.backups.length).toBeGreaterThan(0)
})
