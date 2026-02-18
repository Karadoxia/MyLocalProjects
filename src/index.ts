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

// optional SQLite backing (toggle with USE_SQLITE=1)
const USE_SQLITE = process.env.USE_SQLITE === '1' || process.env.USE_SQLITE === 'true'
let db: any = null

if (USE_SQLITE) {
  try {
    const Database = require('better-sqlite3')
    const DB_FILE = process.env.DB_FILE || path.join(DATA_DIR, 'cart.sqlite')
    fsSync.mkdirSync(DATA_DIR, { recursive: true })
    db = new Database(DB_FILE)
    db.exec('CREATE TABLE IF NOT EXISTS cart_items (id TEXT PRIMARY KEY, name TEXT, price REAL, qty INTEGER)')
    const rows = db.prepare('SELECT id, name, price, qty FROM cart_items').all()
    if (Array.isArray(rows)) cart.items = rows.map((r: any) => ({ id: r.id, name: r.name, price: r.price, qty: r.qty }))
  } catch (err) {
    console.error('sqlite init failed — falling back to JSON persistence', err)
    db = null
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

        // persist (choose SQLite if available, otherwise JSON file)
        if (db) {
          try {
            if (existing) {
              db.prepare('UPDATE cart_items SET qty = ? WHERE id = ?').run(existing.qty, id)
            } else {
              db.prepare('INSERT OR REPLACE INTO cart_items (id, name, price, qty) VALUES (?, ?, ?, ?)').run(id, name, Number(price), 1)
            }
          } catch (err) {
            console.error('sqlite persistence failed', err)
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

    res.writeHead(405, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ error: 'method not allowed' }))
    return
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

server.listen(PORT, HOST, () => {
  const addr = server.address()
  const actualPort = (addr && typeof addr === 'object' && 'port' in addr) ? (addr as any).port : PORT
  console.log(`listening on http://${HOST}:${actualPort}`)
})
