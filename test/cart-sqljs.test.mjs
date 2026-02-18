import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import path from 'path'
import { promises as fs } from 'fs'

test('sql.js-backed cart persists across restarts', async () => {
  const cartPath = path.join(process.cwd(), 'test', `cart-sqljs-${Date.now()}.db`)
  const env = { ...process.env, PORT: '0', USE_SQLJS: '1', CART_FILE: cartPath }
  const server1 = spawn(process.execPath, ['dist/index.js'], { stdio: ['ignore','pipe','pipe'], env })

  let started1 = false
  let port1 = null
  server1.stdout.on('data', d => {
    const s = String(d)
    const m = s.match(/listening on http:\/\/[^:]+:(\d+)/)
    if (m) { port1 = Number(m[1]); started1 = true }
  })

  for (let i=0; i<80 && !started1; i++) await new Promise(r => setTimeout(r, 50))
  assert.ok(started1, 'server1 did not start')

  const add = await fetch(`http://127.0.0.1:${port1}/api/cart`, { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ id: 'sqljs-1', name: 'SQLJS Item', price: 5 }) })
  const addJson = await add.json()
  assert.strictEqual(addJson.total, 1)

  server1.kill()

  // restart with same CART_FILE
  const server2 = spawn(process.execPath, ['dist/index.js'], { stdio: ['ignore','pipe','pipe'], env })
  let started2 = false
  let port2 = null
  server2.stdout.on('data', d => {
    const s = String(d)
    const m = s.match(/listening on http:\/\/[^:]+:(\d+)/)
    if (m) { port2 = Number(m[1]); started2 = true }
  })
  for (let i=0; i<80 && !started2; i++) await new Promise(r => setTimeout(r, 50))
  assert.ok(started2, 'server2 did not start')

  const cartRes = await fetch(`http://127.0.0.1:${port2}/api/cart`)
  const cartJson = await cartRes.json()
  assert.strictEqual(cartJson.total, 1)
  const found = cartJson.items.find(i => i.id === 'sqljs-1')
  assert.ok(found && found.qty === 1)

  server2.kill()
  try { await fs.unlink(cartPath) } catch (e) { /* ignore */ }
})