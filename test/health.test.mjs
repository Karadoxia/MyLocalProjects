import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'

test('server responds to /health and serves homepage', async (t) => {
  const env = { ...process.env, PORT: '0' }
  const server = spawn(process.execPath, ['dist/index.js'], { stdio: ['ignore','pipe','pipe'], env })

  let started = false
  let actualPort = null
  server.stdout.on('data', (d) => {
    const s = String(d)
    const m = s.match(/listening on http:\/\/[^:]+:(\d+)/)
    if (m) { actualPort = Number(m[1]); started = true }
  })

  // wait for server to start (or timeout)
  for (let i = 0; i < 80 && !started; i++) await new Promise(r => setTimeout(r, 50))
  assert.ok(started, 'server did not start')

  const PORT = actualPort

  const res = await fetch(`http://127.0.0.1:${PORT}/health`)
  const body = await res.text()
  assert.strictEqual(body, 'ok')

  const htmlRes = await fetch(`http://127.0.0.1:${PORT}/`)
  const html = await htmlRes.text()
  assert.ok(html.includes('Level up with'))

  // cart API should start empty
  const cartRes1 = await fetch(`http://127.0.0.1:${PORT}/api/cart`)
  const cartJson1 = await cartRes1.json()
  assert.strictEqual(cartJson1.total, 0)

  // add an item
  const add = await fetch(`http://127.0.0.1:${PORT}/api/cart`, { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ id: 'test-1', name: 'Test Item', price: 9.5 }) })
  const addJson = await add.json()
  assert.strictEqual(addJson.total, 1)
  assert.ok(Array.isArray(addJson.items) && addJson.items.length >= 1)

  // cart shows the added item
  const cartRes2 = await fetch(`http://127.0.0.1:${PORT}/api/cart`)
  const cartJson2 = await cartRes2.json()
  assert.strictEqual(cartJson2.total, 1)
  const found = cartJson2.items.find(i => i.id === 'test-1')
  assert.ok(found && found.qty === 1)

  server.kill()
})