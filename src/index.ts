import http from "http"
import { promises as fs } from "fs"
import * as fsSync from "fs"
import path from "path"

const PORT = Number(process.env.PORT ?? 3000)
const HOST = process.env.HOST || "127.0.0.1"
const PUBLIC_DIR = path.resolve(process.cwd(), "public")

// persistence configuration (overridable by env)
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(process.cwd(), 'data'))
const CART_FILE = process.env.CART_FILE || path.join(DATA_DIR, 'cart.json')
const BACKUP_DIR = path.resolve(process.cwd(), 'backups')

const mime: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
}

async function serveFile(filePath: string, res: http.ServerResponse) {
  try {
    const data = await fs.readFile(filePath)
    const ext = path.extname(filePath)
    const type = mime[ext] || "application/octet-stream"
    res.writeHead(200, { "Content-Type": type, "Cache-Control": "no-store" })
    res.end(data)
  } catch (err) {
    res.writeHead(404, { "Content-Type": "text/plain" })
    res.end("Not found")
  }
}

// simple in-memory cart API (server-side) + persisted storage
const cart: { items: { id: string; name: string; price: number; qty: number }[] } = { items: [] }

// optional sql.js backing (toggle with USE_SQLJS=1). Falls back to JSON file persistence.
const USE_SQLJS = process.env.USE_SQLJS === '1' || process.env.USE_SQLJS === 'true'
let db: any = null
let sqljsReady = false

if (USE_SQLJS) {
  try {
    const initSqlJs: any = require('sql.js')
    // initialize in background; until ready we fall back to JSON persistence
    initSqlJs().then((SQL: any) => {
      try {
        fsSync.mkdirSync(DATA_DIR, { recursive: true })
        if (fsSync.existsSync(CART_FILE)) {
          const buf = fsSync.readFileSync(CART_FILE)
          db = new SQL.Database(new Uint8Array(buf))
        } else {
          db = new SQL.Database()
          db.run('CREATE TABLE IF NOT EXISTS cart_items (id TEXT PRIMARY KEY, name TEXT, price REAL, qty INTEGER)')
        }

        // load rows into memory
        const stmt = db.prepare('SELECT id, name, price, qty FROM cart_items')
        const items: any[] = []
        while (stmt.step()) {
          const r = stmt.getAsObject()
          items.push({ id: r.id, name: r.name, price: Number(r.price), qty: Number(r.qty) })
        }
        stmt.free()
        cart.items = items
        sqljsReady = true
        console.log('sql.js initialized; persisted cart loaded')
      } catch (err) {
        console.error('sql.js init failed — falling back to JSON persistence', err)
        db = null
        sqljsReady = false
      }
    }).catch((e: any) => {
      console.error('sql.js loader failed', e)
    })
  } catch (err) {
    console.error('sql.js require failed', err)
  }
} else {
  // load persisted cart (synchronous read to avoid race on startup)
  try {
    fsSync.mkdirSync(DATA_DIR, { recursive: true })
    if (fsSync.existsSync(CART_FILE)) {
      const raw = fsSync.readFileSync(CART_FILE, 'utf8')
      const parsed = JSON.parse(raw || '{}')
      if (parsed && Array.isArray(parsed.items)) cart.items = parsed.items
    }
  } catch (err) {
    /* ignore - start with empty cart */
  }
}

async function readJson(req: http.IncomingMessage) {
  return new Promise<any>((resolve, reject) => {
    let body = ""
    req.on("data", (c) => (body += c.toString()))
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {})
      } catch (err) {
        reject(err)
      }
    })
    req.on("error", reject)
  })
}

const server = http.createServer(async (req, res) => {
  const url = req.url || "/"
  console.log(`[req] ${req.method} ${url}`)

  // API: /api/cart
  if (url.startsWith("/api/cart")) {
    const method = req.method || "GET"
    if (method === "GET") {
      const total = cart.items.reduce((s, it) => s + it.qty, 0)
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ total, items: cart.items }))
      return
    }

    if (method === "POST") {
      try {
        const body = await readJson(req)
        const { id, name, price = 0 } = body
        if (!id || !name) {
          res.writeHead(400, { "Content-Type": "application/json" })
          res.end(JSON.stringify({ error: 'missing id or name' }))
          return
        }
        const existing = cart.items.find((i) => i.id === id)
        if (existing) existing.qty += 1
        else cart.items.push({ id, name, price: Number(price), qty: 1 })

        // persist (choose sql.js if available, otherwise JSON file)
        if (db) {
          try {
            if (existing) {
              db.prepare('UPDATE cart_items SET qty = ? WHERE id = ?').run(existing.qty, id)
            } else {
              db.prepare('INSERT OR REPLACE INTO cart_items (id, name, price, qty) VALUES (?, ?, ?, ?)').run(id, name, Number(price), 1)
            }
            // if running with sql.js, export binary DB immediately
            try {
              if (typeof (db as any).export === 'function') {
                const exported = (db as any).export()
                await fs.mkdir(DATA_DIR, { recursive: true })
                await fs.writeFile(CART_FILE, Buffer.from(exported))
              }
            } catch (err) {
              console.error('sql.js persistence failed', err)
            }
          } catch (err) {
            console.error('db persistence failed', err)
          }
        } else {
          try {
            await fs.mkdir(DATA_DIR, { recursive: true })
            await fs.writeFile(CART_FILE + '.tmp', JSON.stringify({ items: cart.items }), 'utf8')
            await fs.rename(CART_FILE + '.tmp', CART_FILE)
          } catch (err) {
            console.error('cart persistence failed', err)
          }
        }

        const total = cart.items.reduce((s, it) => s + it.qty, 0)
        res.writeHead(201, { "Content-Type": "application/json" })
        res.end(JSON.stringify({ total, items: cart.items }))
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" })
        res.end(JSON.stringify({ error: 'invalid json' }))
      }
      return
    }

    if (method === "DELETE") {
      // clear cart (testing/dev helper)
      cart.items.length = 0
      try {
        if (db) {
          db.prepare('DELETE FROM cart_items').run()
        } else {
          await fs.unlink(CART_FILE).catch(() => {})
        }
      } catch (err) {
        console.error('failed to clear cart', err)
      }
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ total: 0, items: [] }))
      return
    }

    res.writeHead(405, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ error: 'method not allowed' }))
    return
  }

  // metrics endpoint (Prometheus exposition format)
  if (url === '/metrics') {
    const cartCount = cart.items.reduce((s, i) => s + i.qty, 0)
    const uniqueItems = cart.items.length
    const uptime = process.uptime()
    const body = `# HELP cart_items_total total number of items in cart\n# TYPE cart_items_total gauge\ncart_items_total ${cartCount}\n# HELP cart_unique_items number of unique SKUs in cart\n# TYPE cart_unique_items gauge\ncart_unique_items ${uniqueItems}\n# HELP process_uptime_seconds process uptime in seconds\n# TYPE process_uptime_seconds gauge\nprocess_uptime_seconds ${uptime}\n`
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' })
    res.end(body)
    return
  }

  // list backups
  if (url.startsWith('/api/backups') && (req.method === 'GET' || !req.method)) {
    try {
      fsSync.mkdirSync(BACKUP_DIR, { recursive: true })
      const files = fsSync.readdirSync(BACKUP_DIR).filter(f => f.startsWith('cart-')).sort().reverse()
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ backups: files }))
      return
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'failed to list backups' }))
      return
    }
  }

  // create a backup of the current cart
  if (url === '/api/backup' && req.method === 'POST') {
    try {
      fsSync.mkdirSync(BACKUP_DIR, { recursive: true })
      // ensure CART_FILE exists for JSON mode, or persist DB first
      if (db && typeof db.export === 'function') {
        try {
          const exported = db.export()
          fsSync.writeFileSync(CART_FILE, Buffer.from(exported))
        } catch (err) {
          console.error('failed to persist sql.js DB before backup', err)
        }
      }
      if (!fsSync.existsSync(CART_FILE)) {
        // create an empty cart file if missing
        fsSync.writeFileSync(CART_FILE, JSON.stringify({ items: cart.items }), 'utf8')
      }
      const stamp = new Date().toISOString().replace(/[:.]/g, '-')
      const out = path.join(BACKUP_DIR, `cart-${stamp}.json`)
      fsSync.copyFileSync(CART_FILE, out)
      res.writeHead(201, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ backedUp: path.basename(out) }))
      return
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'backup failed' }))
      return
    }
  }

  // restore from a named backup (body: { file: "cart-...json" })
  if (url === '/api/restore' && req.method === 'POST') {
    try {
      const body = await readJson(req)
      const file = body && body.file
      if (!file) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'missing file' })); return }
      const src = path.join(BACKUP_DIR, file)
      if (!fsSync.existsSync(src)) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'not found' })); return }
      // copy into CART_FILE
      fsSync.copyFileSync(src, CART_FILE)

      // reload into memory (JSON or sql.js)
      if (USE_SQLJS) {
        try {
          const initSqlJs = require('sql.js')
          const SQL = await initSqlJs()
          const buf = fsSync.readFileSync(CART_FILE)
          const uint8 = new Uint8Array(buf)
          db = new SQL.Database(uint8)
          const stmt = db.prepare('SELECT id, name, price, qty FROM cart_items')
          const items: any[] = []
          while (stmt.step()) { const r = stmt.getAsObject(); items.push({ id: r.id, name: r.name, price: Number(r.price), qty: Number(r.qty) }) }
          stmt.free()
          cart.items = items
        } catch (err) {
          console.error('restore into sql.js failed', err)
        }
      } else {
        try {
          const raw = fsSync.readFileSync(CART_FILE, 'utf8')
          const parsed = JSON.parse(raw || '{}')
          cart.items = Array.isArray(parsed.items) ? parsed.items : []
        } catch (err) {
          console.error('restore failed to parse JSON', err)
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ restored: file }))
      return
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'restore failed' }))
      return
    }
  }

  if (url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" })
    res.end("ok")
    return
  }

  let pathname = decodeURIComponent(url.split("?")[0])
  if (pathname === "/") pathname = "/index.html"
  const filePath = path.join(PUBLIC_DIR, pathname)

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(400, { "Content-Type": "text/plain" })
    res.end("Bad request")
    return
  }

  try {
    const stat = await fs.stat(filePath)
    if (stat.isFile()) return await serveFile(filePath, res)
  } catch {
    // fallthrough to serve index.html
  }

  await serveFile(path.join(PUBLIC_DIR, "index.html"), res)
})

// persist sql.js DB to disk (if available)
async function persistSqlJsToDisk() {
  try {
    if (db && typeof (db as any).export === 'function') {
      const exported = (db as any).export()
      await fs.mkdir(DATA_DIR, { recursive: true })
      await fs.writeFile(CART_FILE, Buffer.from(exported))
      console.log('sql.js checkpoint written to', CART_FILE)
    }
  } catch (err) {
    console.error('sql.js checkpoint failed', err)
  }
}

// periodic checkpoint (only active when sql.js mode enabled)
const SQLJS_CHECKPOINT_MS = Number(process.env.SQLJS_CHECKPOINT_MS ?? 5000)
let _checkpointTimer: NodeJS.Timeout | null = null
if (USE_SQLJS) {
  _checkpointTimer = setInterval(() => {
    if (db && typeof (db as any).export === 'function') {
      persistSqlJsToDisk().catch(err => console.error('checkpoint error', err))
    }
  }, SQLJS_CHECKPOINT_MS)
}

// graceful shutdown: persist DB and exit
async function gracefulShutdown(signal: string) {
  console.log(`received ${signal} — performing graceful shutdown`)
  try {
    if (_checkpointTimer) clearInterval(_checkpointTimer)
    await persistSqlJsToDisk()
  } catch (err) {
    console.error('error during graceful shutdown', err)
  }
  process.exit(0)
}
process.on('SIGINT', () => void gracefulShutdown('SIGINT'))
process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'))

server.listen(PORT, HOST, () => {
  const addr = server.address()
  const actualPort = (addr && typeof addr === 'object' && 'port' in addr) ? (addr as any).port : PORT
  console.log(`listening on http://${HOST}:${actualPort}`)
})
