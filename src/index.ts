import http from "http"
import { promises as fs } from "fs"
import path from "path"

const PORT = Number(process.env.PORT) || 3000
const HOST = process.env.HOST || "127.0.0.1"
const PUBLIC_DIR = path.resolve(process.cwd(), "public")

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

const server = http.createServer(async (req, res) => {
  const url = req.url || "/"

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
  console.log(`listening on http://${HOST}:${PORT}`)
})
