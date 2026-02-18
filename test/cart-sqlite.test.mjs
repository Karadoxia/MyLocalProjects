import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import path from 'path'
import { promises as fs } from 'fs'

// verify persistence when USE_SQLITE=1
import { existsSync } from 'node:fs'

// skip if native sqlite driver not installed in this environment
let hasNativeSqlite = true
try {
  require.resolve('better-sqlite3')
} catch (e) {
  hasNativeSqlite = false
}

if (!hasNativeSqlite) {
  test.skip('sqlite-backed cart persists across restarts (native driver not installed)')
} else {
  test('sqlite-backed cart persists across restarts', async () => {
    const dbPath = path.join(process.cwd(), 'test', `cart-${Date.now()}.sqlite`)
    const env = { ...process.env, PORT: '0', USE_SQLITE: '1', DB_FILE: dbPath }
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

    const add = await fetch(`http://127.0.0.1:${port1}/api/cart`, { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ id: 'sqlite-1', name: 'SQLite Item', price: 5 }) })
    const addJson = await add.json()
    assert.strictEqual(addJson.total, 1)

    server1.kill()

    // restart with same DB_FILE
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
    const found = cartJson.items.find(i => i.id === 'sqlite-1')
    assert.ok(found && found.qty === 1)

    server2.kill()
    try { await fs.unlink(dbPath) } catch (e) { /* ignore */ }
  })
}
