import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import path from 'path'
import http from 'http'

// Starts the server and waits for it to announce its port on stdout
async function startServer(env = {}) {
  const merged = { ...process.env, PORT: '0', ...env }
  const server = spawn(process.execPath, ['dist/index.js'], { stdio: ['ignore', 'pipe', 'pipe'], env: merged })
  let started = false
  let port = null
  server.stdout.on('data', (d) => {
    const s = String(d)
    const m = s.match(/listening on http:\/\/[^:]+:(\d+)/)
    if (m) { port = Number(m[1]); started = true }
  })
  for (let i = 0; i < 80 && !started; i++) await new Promise(r => setTimeout(r, 50))
  if (!started) throw new Error('server did not start')
  return { server, port }
}

test('GET /api/agent/prompt returns fallback prompt when agent missing', async () => {
  const { server, port } = await startServer()
  const res = await fetch(`http://127.0.0.1:${port}/api/agent/prompt`)
  assert.strictEqual(res.status, 200)
  const j = await res.json()
  assert.ok(j.prompt && typeof j.prompt === 'string' && j.prompt.includes('Orchestrator'))
  server.kill()
})

test('POST /api/agent/scrape returns title from a local page (fallback scrape)', async () => {
  const { server, port } = await startServer()

  // start a tiny HTTP server to act as the scraped target
  const target = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end('<html><head><title>Agent Test Page</title></head><body>ok</body></html>')
  })

  await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve))
  const targetPort = (target.address()).port

  const r = await fetch(`http://127.0.0.1:${port}/api/agent/scrape`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: `http://127.0.0.1:${targetPort}/` })
  })
  assert.strictEqual(r.status, 200)
  const j = await r.json()
  assert.strictEqual(j.title, 'Agent Test Page')

  target.close()
  server.kill()
})

test('POST /api/agent/demo creates an item and backup', async () => {
  const { server, port } = await startServer()
  const r = await fetch(`http://127.0.0.1:${port}/api/agent/demo`, { method: 'POST' })
  assert.strictEqual(r.status, 200)
  const j = await r.json()
  assert.ok(j.ok === true)
  assert.strictEqual(j.item, 'agent-demo')

  const cart = await fetch(`http://127.0.0.1:${port}/api/cart`)
  const cj = await cart.json()
  const found = cj.items.find(i => i.id === 'agent-demo')
  assert.ok(found && found.qty >= 1)

  const backups = await fetch(`http://127.0.0.1:${port}/api/backups`)
  const bj = await backups.json()
  assert.ok(Array.isArray(bj.backups) && bj.backups.length > 0)

  server.kill()
})
