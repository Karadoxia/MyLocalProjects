import http from "http"

const PORT = Number(process.env.PORT) || 3000

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" })
    res.end("ok")
    return
  }

  res.writeHead(200, { "Content-Type": "text/plain" })
  res.end("Hello from new-project")
})

server.listen(PORT, "127.0.0.1", () => {
  console.log(`listening on http://127.0.0.1:${PORT}`)
})
